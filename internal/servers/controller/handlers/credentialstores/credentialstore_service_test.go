package credentialstores

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/credentialstores"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete"}

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms)
	}

	_, prjNoStores := iam.TestScopes(t, iamRepo)
	_, prj := iam.TestScopes(t, iamRepo)

	var wantStores []*pb.CredentialStore
	for _, s := range vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 10) {
		wantStores = append(wantStores, &pb.CredentialStore{
			Id:                s.GetPublicId(),
			ScopeId:           prj.GetPublicId(),
			Scope:             &scopes.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
			CreatedTime:       s.GetCreateTime().GetTimestamp(),
			UpdatedTime:       s.GetUpdateTime().GetTimestamp(),
			Version:           s.GetVersion(),
			Type:              credential.VaultSubtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Attributes: func() *structpb.Struct {
				attrs := &pb.VaultCredentialStoreAttributes{
					Address: s.GetVaultAddress(),
				}
				st, err := handlers.ProtoToStruct(attrs)
				require.NoError(t, err)
				return st
			}(),
		})
	}

	cases := []struct {
		name string
		req  *pbs.ListCredentialStoresRequest
		res  *pbs.ListCredentialStoresResponse
		err  error
	}{
		{
			name: "List Many Stores",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId()},
			res:  &pbs.ListCredentialStoresResponse{Items: wantStores},
		},
		{
			name: "List No Stores",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prjNoStores.GetPublicId()},
			res:  &pbs.ListCredentialStoresResponse{},
		},
		{
			name: "Filter to One Store",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantStores[1].GetId())},
			res:  &pbs.ListCredentialStoresResponse{Items: wantStores[1:2]},
		},
		{
			name: "Filter to No Store",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res:  &pbs.ListCredentialStoresResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewService(repoFn, iamRepoFn)
			require.NoError(t, err, "Couldn't create new host set service.")

			// Test non-anonymous listing
			got, gErr := s.ListCredentialStores(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err), "ListCredentialStore(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(t, gErr)
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform()))

			// Test anonymous listing
			got, gErr = s.ListCredentialStores(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
			require.NoError(t, gErr)
			assert.Len(t, got.Items, len(tc.res.Items))
			for _, item := range got.GetItems() {
				require.Nil(t, item.CreatedTime)
				require.Nil(t, item.UpdatedTime)
				require.Zero(t, item.Version)
			}
		})
	}
}
