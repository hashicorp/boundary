package credentialstores

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/credentialstores"
	scopepb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
			Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
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

func TestCreate(t *testing.T) {
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

	_, prj := iam.TestScopes(t, iamRepo)
	defaultCs := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	defaultCreated := defaultCs.GetCreateTime().GetTimestamp()

	v := vault.NewTestVaultServer(t, vault.TestNoTLS)
	secret := v.CreateToken(t)
	token := secret.Auth.ClientToken

	cases := []struct {
		name     string
		req      *pbs.CreateCredentialStoreRequest
		res      *pbs.CreateCredentialStoreResponse
		idPrefix string
		err      error
	}{
		{
			name: "Create a valid vault CredentialStore",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
				Type:        credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					p := &pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					}
					attrs, err := handlers.ProtoToStruct(p)
					require.NoError(t, err)
					return attrs
				}(),
			}},
			idPrefix: vault.CredentialStorePrefix + "_",
			res: &pbs.CreateCredentialStoreResponse{
				Uri: fmt.Sprintf("credential-stores/%s_", vault.CredentialStorePrefix),
				Item: &pb.CredentialStore{
					Id:          defaultCs.GetPublicId(),
					ScopeId:     prj.GetPublicId(),
					CreatedTime: defaultCs.GetCreateTime().GetTimestamp(),
					UpdatedTime: defaultCs.GetUpdateTime().GetTimestamp(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Scope:       &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:     1,
					Type:        credential.VaultSubtype.String(),
					Attributes: func() *structpb.Struct {
						p := &pb.VaultCredentialStoreAttributes{
							Address:        v.Addr,
							VaultTokenHmac: "<hmac>",
						}
						attrs, err := handlers.ProtoToStruct(p)
						require.NoError(t, err)
						return attrs
					}(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Id:      vault.CredentialStorePrefix + "_notallowed",
				Type:    credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					p := &pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					}
					attrs, err := handlers.ProtoToStruct(p)
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				CreatedTime: timestamppb.Now(),
				Type:        credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					p := &pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					}
					attrs, err := handlers.ProtoToStruct(p)
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				UpdatedTime: timestamppb.Now(),
				Type:        credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					p := &pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					}
					attrs, err := handlers.ProtoToStruct(p)
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				UpdatedTime: timestamppb.Now(),
				Type:        credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					p := &pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					}
					attrs, err := handlers.ProtoToStruct(p)
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify type",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Attributes: func() *structpb.Struct {
					p := &pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					}
					attrs, err := handlers.ProtoToStruct(p)
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify vault address",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					p := &pb.VaultCredentialStoreAttributes{
						VaultToken: token,
					}
					attrs, err := handlers.ProtoToStruct(p)
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify vault token",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					p := &pb.VaultCredentialStoreAttributes{
						Address: v.Addr,
					}
					attrs, err := handlers.ProtoToStruct(p)
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Attributes must be valid for vault type",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					p := &pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					}
					attrs, err := handlers.ProtoToStruct(p)
					require.NoError(t, err)
					attrs.Fields["invalid"] = structpb.NewStringValue("foo")
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := NewService(repoFn, iamRepoFn)
			require.NoError(err, "Error when getting new credential store service.")

			got, gErr := s.CreateCredentialStore(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetItem().GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "CreateCredentialStore(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(gErr)
			if tc.res == nil {
				require.Nil(got)
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				assert.True(strings.HasPrefix(got.GetItem().GetId(), tc.idPrefix))
				gotCreateTime := got.GetItem().GetCreatedTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime()

				// Verify it is a credential store created after the test setup's default credential store
				assert.True(gotCreateTime.AsTime().After(defaultCreated.AsTime()), "New credential store should have been created after default credential store. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.AsTime().After(defaultCreated.AsTime()), "New credential store should have been updated after default credential store. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
				if _, ok := got.Item.Attributes.Fields["vault_token_hmac"]; ok {
					assert.NotEqual(tc.req.Item.Attributes.Fields["vault_token"], got.Item.Attributes.Fields["vault_token_hmac"])
					got.Item.Attributes.Fields["vault_token_hmac"] = structpb.NewStringValue("<hmac>")
				}
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeatedFields(got)), "CreateCredentialStore(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}
