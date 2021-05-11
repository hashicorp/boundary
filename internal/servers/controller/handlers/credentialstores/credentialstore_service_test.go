package credentialstores

import (
	"encoding/base64"
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
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
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
				attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
					Address: s.GetVaultAddress(),
					// TODO: Add all fields including VaultTokenHmac, ClientCert, tls related fields, namespace, etc...
				})
				require.NoError(t, err)
				return attrs
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

	v := vault.NewTestVaultServer(t, vault.TestClientTLS)
	secret := v.CreateToken(t)
	token := secret.Auth.ClientToken

	cases := []struct {
		name     string
		req      *pbs.CreateCredentialStoreRequest
		res      *pbs.CreateCredentialStoreResponse
		idPrefix string
		err      error
		wantErr  bool
	}{
		{
			name: "missing ca certificate",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:              v.Addr,
						VaultToken:           token,
						ClientCertificate:    wrapperspb.String(string(v.ClientCert)),
						ClientCertificateKey: wrapperspb.String(string(v.ClientKey)),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			idPrefix: vault.CredentialStorePrefix + "_",
			wantErr:  true,
		},
		{
			name: "Bad token",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:              v.Addr,
						VaultToken:           "madeup",
						VaultCaCert:          wrapperspb.String(string(v.CaCert)),
						ClientCertificate:    wrapperspb.String(string(v.ClientCert)),
						ClientCertificateKey: wrapperspb.String(string(v.ClientKey)),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			idPrefix: vault.CredentialStorePrefix + "_",
			wantErr:  true,
		},
		{
			name: "Define only client cert",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:           v.Addr,
						VaultToken:        token,
						VaultCaCert:       wrapperspb.String(string(v.CaCert)),
						ClientCertificate: wrapperspb.String(string(v.ClientCert)),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			idPrefix: vault.CredentialStorePrefix + "_",
			err:      handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Define only client cert key",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:              v.Addr,
						VaultToken:           token,
						VaultCaCert:          wrapperspb.String(string(v.CaCert)),
						ClientCertificateKey: wrapperspb.String(string(v.ClientKey)),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			idPrefix: vault.CredentialStorePrefix + "_",
			err:      handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Id:      vault.CredentialStorePrefix + "_notallowed",
				Type:    credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					})
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
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					})
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
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					})
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
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					})
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
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					})
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
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						VaultToken: token,
					})
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
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address: v.Addr,
					})
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
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:    v.Addr,
						VaultToken: token,
					})
					require.NoError(t, err)
					attrs.Fields["invalid"] = structpb.NewStringValue("foo")
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		// This must be executed last
		{
			name: "Create a valid vault CredentialStore",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
				Type:        credential.VaultSubtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:              v.Addr,
						VaultToken:           token,
						VaultCaCert:          wrapperspb.String(string(v.CaCert)),
						ClientCertificate:    wrapperspb.String(string(v.ClientCert)),
						ClientCertificateKey: wrapperspb.String(string(v.ClientKey)),
					})
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
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							VaultCaCert:    wrapperspb.String(string(v.CaCert)),
							Address:        v.Addr,
							VaultTokenHmac: "<hmac>",
						})
						require.NoError(t, err)
						return attrs
					}(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := NewService(repoFn, iamRepoFn)
			require.NoError(err, "Error when getting new credential store service.")

			got, gErr := s.CreateCredentialStore(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetItem().GetScopeId()), tc.req)
			if tc.wantErr || tc.err != nil {
				require.Error(gErr)
				if tc.err != nil {
					assert.True(errors.Is(gErr, tc.err), "CreateCredentialStore(...) got error %v, wanted %v", gErr, tc.err)
				}
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

func TestGet(t *testing.T) {
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

	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	s, err := NewService(repoFn, iamRepoFn)
	require.NoError(t, err)

	cases := []struct {
		name string
		id   string
		res  *pbs.GetCredentialStoreResponse
		err  error
	}{
		{
			name: "success",
			id:   store.GetPublicId(),
			res: &pbs.GetCredentialStoreResponse{
				Item: &pb.CredentialStore{
					Id:                store.GetPublicId(),
					ScopeId:           store.GetScopeId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetScopeId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              credential.VaultSubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       store.CreateTime.GetTimestamp(),
					UpdatedTime:       store.UpdateTime.GetTimestamp(),
					Version:           1,
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							Address:        store.GetVaultAddress(),
							VaultTokenHmac: base64.RawURLEncoding.EncodeToString(store.Token().GetTokenHmac()),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
		},
		{
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", vault.CredentialStorePrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", static.HostPrefix),
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.GetCredentialStoreRequest{Id: tc.id}
			// Test non-anonymous get
			got, gErr := s.GetCredentialStore(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), req)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err))
				return
			}
			require.NoError(t, gErr)
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform()))

			// Test anonymous get
			got, gErr = s.GetCredentialStore(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), req)
			require.NoError(t, gErr)
			require.Nil(t, got.Item.CreatedTime)
			require.Nil(t, got.Item.UpdatedTime)
			require.Zero(t, got.Item.Version)
		})
	}
}

func TestDelete(t *testing.T) {
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

	store := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)[0]
	s, err := NewService(repoFn, iamRepoFn)
	require.NoError(t, err)

	cases := []struct {
		name string
		id   string
		err  error
	}{
		{
			name: "success",
			id:   store.GetPublicId(),
		},
		{
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", vault.CredentialStorePrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", static.HostPrefix),
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gErr := s.DeleteCredentialStore(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), &pbs.DeleteCredentialStoreRequest{Id: tc.id})
			assert.Nil(t, got)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err))
				return
			}
			require.NoError(t, gErr)
			g, err := s.GetCredentialStore(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), &pbs.GetCredentialStoreRequest{Id: tc.id})
			assert.Nil(t, g)
			assert.True(t, errors.Is(err, handlers.NotFoundError()))
		})
	}
}

func TestUpdate(t *testing.T) {
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
	ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())

	s, err := NewService(repoFn, iamRepoFn)
	require.NoError(t, err)

	freshStore := func() (*vault.CredentialStore, func()) {
		t.Helper()
		st := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
		clean := func() {
			_, err := s.DeleteCredentialStore(ctx, &pbs.DeleteCredentialStoreRequest{Id: st.GetPublicId()})
			require.NoError(t, err)
		}
		return st, clean
	}

	fieldmask := func(paths ...string) *fieldmaskpb.FieldMask {
		return &fieldmaskpb.FieldMask{Paths: paths}
	}

	v := vault.NewTestVaultServer(t, vault.TestClientTLS)
	secret := v.CreateToken(t)
	token := secret.Auth.ClientToken
	_ = token

	successCases := []struct {
		name string
		req  *pbs.UpdateCredentialStoreRequest
		res  func(*pb.CredentialStore) *pb.CredentialStore
	}{
		{
			name: "name and description",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("name", "description"),
				Item: &pb.CredentialStore{
					Name:        wrapperspb.String("basic"),
					Description: wrapperspb.String("basic"),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Name = wrapperspb.String("basic")
				out.Description = wrapperspb.String("basic")
				// TODO(ICU-1483): Expect a vault token hmac to be set in the update response
				delete(out.GetAttributes().Fields, "vault_token_hmac")
				return out
			},
		},
		{
			name: "update address",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.address"),
				Item: &pb.CredentialStore{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							Address: v.Addr,
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Attributes.Fields["address"] = structpb.NewStringValue(v.Addr)
				// TODO(ICU-1483): Expect a vault token hmac to be set in the update response
				delete(out.GetAttributes().Fields, "vault_token_hmac")
				return out
			},
		},
		{
			name: "update namespace",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.namespace"),
				Item: &pb.CredentialStore{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							Namespace: wrapperspb.String("update namespace"),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Attributes.Fields["namespace"] = structpb.NewStringValue("update namespace")
				// TODO(ICU-1483): Expect a vault token hmac to be set in the update response
				delete(out.GetAttributes().Fields, "vault_token_hmac")
				return out
			},
		},
		{
			name: "update tls server name",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.tls_server_name"),
				Item: &pb.CredentialStore{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							TlsServerName: wrapperspb.String("UpdateTlsServerName"),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Attributes.Fields["tls_server_name"] = structpb.NewStringValue("UpdateTlsServerName")
				// TODO(ICU-1483): Expect a vault token hmac to be set in the update response
				delete(out.GetAttributes().Fields, "vault_token_hmac")
				return out
			},
		},
		{
			name: "update TlsSkipVerify",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.tls_skip_verify"),
				Item: &pb.CredentialStore{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							TlsSkipVerify: wrapperspb.Bool(true),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Attributes.Fields["tls_skip_verify"] = structpb.NewBoolValue(true)
				// TODO(ICU-1483): Expect a vault token hmac to be set in the update response
				delete(out.GetAttributes().Fields, "vault_token_hmac")
				return out
			},
		},
		{
			name: "update ca cert",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.vault_ca_cert"),
				Item: &pb.CredentialStore{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							VaultCaCert: wrapperspb.String(string(v.CaCert)),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Attributes.Fields["vault_ca_cert"] = structpb.NewStringValue(string(v.CaCert))
				// TODO(ICU-1483): Expect a vault token hmac to be set in the update response
				delete(out.GetAttributes().Fields, "vault_token_hmac")
				return out
			},
		},
		// TODO(ICU-1488): Fix field masks to treat certificate and key as a single value
		// {
		// 	name: "update client cert",
		// 	req: &pbs.UpdateCredentialStoreRequest{
		// 		UpdateMask: fieldmask("attributes.client_certificate", "attributes.client_certificate_key"),
		// 		Item: &pb.CredentialStore{
		// 			Attributes: func() *structpb.Struct {
		// 				attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
		// 					ClientCertificate: wrapperspb.String(string(v.ClientCert)),
		// 					CertificateKey: wrapperspb.String(string(v.ClientKey)),
		// 				})
		// 				require.NoError(t, err)
		// 				return attrs
		// 			}(),
		// 		},
		// 	},
		// 	res: func(in *pb.CredentialStore) *pb.CredentialStore {
		// 		out := proto.Clone(in).(*pb.CredentialStore)
		// 		out.Attributes.Fields["client_certificate"] = structpb.NewStringValue(string(v.ClientCert))
		// 		out.Attributes.Fields["client_certificate_key"] = structpb.NewStringValue(string(v.ClientKey))
		// 		// TODO(ICU-1483): Expect a vault token hmac to be set in the update response
		// 		delete(out.GetAttributes().Fields, "vault_token_hmac")
		// 		return out
		// 	},
		// },
	}

	for _, tc := range successCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			st, cleanup := freshStore()
			defer cleanup()

			if tc.req.Item.GetVersion() == 0 {
				tc.req.Item.Version = 1
			}
			if tc.req.GetId() == "" {
				tc.req.Id = st.GetPublicId()
			}
			resToChange, err := s.GetCredentialStore(ctx, &pbs.GetCredentialStoreRequest{Id: st.GetPublicId()})
			require.NoError(err)
			want := &pbs.UpdateCredentialStoreResponse{Item: tc.res(resToChange.GetItem())}

			got, gErr := s.UpdateCredentialStore(ctx, tc.req)
			require.NoError(gErr)
			require.NotNil(got)

			gotUpdateTime := got.GetItem().GetUpdatedTime()
			created := st.GetCreateTime().GetTimestamp()
			assert.True(gotUpdateTime.AsTime().After(created.AsTime()), "Should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

			want.Item.UpdatedTime = got.Item.UpdatedTime

			assert.EqualValues(2, got.Item.Version)
			want.Item.Version = 2

			assert.Empty(cmp.Diff(got, want, protocmp.Transform()))
		})
	}

	// cant update read only fields
	st, cleanup := freshStore()
	defer cleanup()

	roCases := []struct {
		path string
		item *pb.CredentialStore
	}{
		{
			path: "type",
			item: &pb.CredentialStore{Type: "something"},
		},
		{
			path: "scope_id",
			item: &pb.CredentialStore{ScopeId: "global"},
		},
		{
			path: "updated_time",
			item: &pb.CredentialStore{UpdatedTime: timestamppb.Now()},
		},
		{
			path: "created_time",
			item: &pb.CredentialStore{UpdatedTime: timestamppb.Now()},
		},
		{
			path: "authorized actions",
			item: &pb.CredentialStore{AuthorizedActions: append(testAuthorizedActions, "another")},
		},
	}
	for _, tc := range roCases {
		t.Run(fmt.Sprintf("ReadOnlyField/%s", tc.path), func(t *testing.T) {
			req := &pbs.UpdateCredentialStoreRequest{
				Id:         st.GetPublicId(),
				Item:       tc.item,
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{tc.path}},
			}
			req.Item.Version = st.Version

			got, gErr := s.UpdateCredentialStore(ctx, req)
			assert.Error(t, gErr)
			assert.Truef(t, errors.Is(gErr, handlers.ApiErrorWithCode(codes.InvalidArgument)), "got error %v, wanted invalid argument", gErr)
			assert.Nil(t, got)
		})
	}
}
