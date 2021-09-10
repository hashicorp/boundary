package credentialstores

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
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
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
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
			Type:              vault.Subtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Attributes: func() *structpb.Struct {
				attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
					Address:                  wrapperspb.String(s.GetVaultAddress()),
					TokenHmac:                base64.RawURLEncoding.EncodeToString(s.Token().GetTokenHmac()),
					ClientCertificate:        wrapperspb.String(string(s.ClientCertificate().GetCertificate())),
					ClientCertificateKeyHmac: base64.RawURLEncoding.EncodeToString(s.ClientCertificate().GetCertificateKeyHmac()),
					// TODO: Add all fields including tls related fields, namespace, etc...
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
			assert.ElementsMatch(t, got.Items, tc.res.Items)

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
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	defaultCreated := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0].GetCreateTime().GetTimestamp()

	cleanup := func(s Service) {
		ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())
		r, err := s.ListCredentialStores(ctx, &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId()})
		require.NoError(t, err)
		for _, i := range r.GetItems() {
			_, err := s.DeleteCredentialStore(ctx, &pbs.DeleteCredentialStoreRequest{Id: i.GetId()})
			require.NoError(t, err)
		}
	}

	v := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestClientTLS))
	newToken := func() string {
		_, token := v.CreateToken(t)
		return token
	}

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
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String(newToken()),
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
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String("madeup"),
						CaCert:               wrapperspb.String(string(v.CaCert)),
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
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:           wrapperspb.String(v.Addr),
						Token:             wrapperspb.String(newToken()),
						CaCert:            wrapperspb.String(string(v.CaCert)),
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
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String(newToken()),
						CaCert:               wrapperspb.String(string(v.CaCert)),
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
			name: "Define key in both client cert payload and key field",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String(newToken()),
						CaCert:               wrapperspb.String(string(v.CaCert)),
						ClientCertificateKey: wrapperspb.String(string(append(v.ClientCert, v.ClientKey...))),
						ClientCertificate:    wrapperspb.String(string(v.ClientKey)),
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
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
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
				Type:        vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
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
				Type:        vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
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
				Type:        vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
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
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify vault VaultAddress",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Token: wrapperspb.String(newToken()),
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
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
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
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
					})
					require.NoError(t, err)
					attrs.Fields["invalid"] = structpb.NewStringValue("foo")
					return attrs
				}(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create a valid vault CredentialStore with client cert and key in same field",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:           wrapperspb.String(v.Addr),
						Token:             wrapperspb.String(newToken()),
						CaCert:            wrapperspb.String(string(v.CaCert)),
						ClientCertificate: wrapperspb.String(string(v.ClientCert) + string(v.ClientKey)),
					})
					require.NoError(t, err)
					return attrs
				}(),
			}},
			idPrefix: vault.CredentialStorePrefix + "_",
			res: &pbs.CreateCredentialStoreResponse{
				Uri: fmt.Sprintf("credential-stores/%s_", vault.CredentialStorePrefix),
				Item: &pb.CredentialStore{
					ScopeId: prj.GetPublicId(),
					Scope:   &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version: 1,
					Type:    vault.Subtype.String(),
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							CaCert:                   wrapperspb.String(string(v.CaCert)),
							Address:                  wrapperspb.String(v.Addr),
							TokenHmac:                "<hmac>",
							ClientCertificate:        wrapperspb.String(string(v.ClientCert)),
							ClientCertificateKeyHmac: "<hmac>",
						})
						require.NoError(t, err)
						return attrs
					}(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialStore",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
				Type:        vault.Subtype.String(),
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String(newToken()),
						CaCert:               wrapperspb.String(string(v.CaCert)),
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
					ScopeId:     prj.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Scope:       &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:     1,
					Type:        vault.Subtype.String(),
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							CaCert:                   wrapperspb.String(string(v.CaCert)),
							Address:                  wrapperspb.String(v.Addr),
							TokenHmac:                "<hmac>",
							ClientCertificate:        wrapperspb.String(string(v.ClientCert)),
							ClientCertificateKeyHmac: "<hmac>",
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
			defer cleanup(s)

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
				if _, ok := got.Item.Attributes.Fields["token_hmac"]; ok {
					assert.NotEqual(tc.req.Item.Attributes.Fields["token"], got.Item.Attributes.Fields["token_hmac"])
					got.Item.Attributes.Fields["token_hmac"] = structpb.NewStringValue("<hmac>")
				}
				if _, ok := got.Item.Attributes.Fields["client_certificate_key_hmac"]; ok {
					assert.NotEqual(tc.req.Item.Attributes.Fields["client_certificate_key_hmac"], got.Item.Attributes.Fields["client_certificate_key_hmac"])
					got.Item.Attributes.Fields["client_certificate_key_hmac"] = structpb.NewStringValue("<hmac>")
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
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
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
					Type:              vault.Subtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       store.CreateTime.GetTimestamp(),
					UpdatedTime:       store.UpdateTime.GetTimestamp(),
					Version:           1,
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							Address:                  wrapperspb.String(store.GetVaultAddress()),
							TokenHmac:                base64.RawURLEncoding.EncodeToString(store.Token().GetTokenHmac()),
							ClientCertificate:        wrapperspb.String(string(store.ClientCertificate().GetCertificate())),
							ClientCertificateKeyHmac: base64.RawURLEncoding.EncodeToString(store.ClientCertificate().GetCertificateKeyHmac()),
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
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
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
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(rw, rw, kms, sche)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())

	s, err := NewService(repoFn, iamRepoFn)
	require.NoError(t, err)

	fieldmask := func(paths ...string) *fieldmaskpb.FieldMask {
		return &fieldmaskpb.FieldMask{Paths: paths}
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	v := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestClientTLS), vault.WithClientKey(key))
	_, token1b := v.CreateToken(t)
	clientCert, err := vault.NewClientCertificate(v.ClientCert, v.ClientKey)
	require.NoError(t, err)

	v2 := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestClientTLS), vault.WithClientKey(key))
	_, token2 := v2.CreateToken(t)
	clientCert2, err := vault.NewClientCertificate(v2.ClientCert, v2.ClientKey)
	require.NoError(t, err)

	freshStore := func() (*vault.CredentialStore, func()) {
		t.Helper()
		secret, token1a := v.CreateToken(t)
		accessor := secret.Auth.Accessor

		st := vault.TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), v.Addr, token1a, accessor, vault.WithCACert(v.CaCert), vault.WithClientCert(clientCert))
		clean := func() {
			_, err := s.DeleteCredentialStore(ctx, &pbs.DeleteCredentialStoreRequest{Id: st.GetPublicId()})
			require.NoError(t, err)
		}
		return st, clean
	}

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
				return out
			},
		},
		{
			name: "update connection info",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.address", "attributes.client_certificate", "attributes.client_certificate_key", "attributes.ca_cert", "attributes.token"),
				Item: &pb.CredentialStore{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							Address:              wrapperspb.String(v2.Addr),
							Token:                wrapperspb.String(token2),
							ClientCertificate:    wrapperspb.String(string(clientCert2.Certificate)),
							ClientCertificateKey: wrapperspb.String(string(clientCert2.CertificateKey)),
							CaCert:               wrapperspb.String(string(v2.CaCert)),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Attributes.Fields["address"] = structpb.NewStringValue(v2.Addr)
				out.Attributes.Fields["client_certificate"] = structpb.NewStringValue(string(clientCert2.Certificate))
				out.Attributes.Fields["ca_cert"] = structpb.NewStringValue(string(v2.CaCert))
				out.Attributes.Fields["token_hmac"] = structpb.NewStringValue("<hmac>")
				out.Attributes.Fields["client_certificate_key_hmac"] = structpb.NewStringValue("<hmac>")
				return out
			},
		},
		{
			name: "update token",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.token"),
				Item: &pb.CredentialStore{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							Token: wrapperspb.String(token1b),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Attributes.Fields["token_hmac"] = structpb.NewStringValue("<hmac>")
				return out
			},
		},
		{
			name: "unset certificate",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.client_certificate", "attributes.client_certificate_key"),
				Item:       &pb.CredentialStore{},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				delete(out.Attributes.Fields, "client_certificate")
				delete(out.Attributes.Fields, "client_certificate_key_hmac")
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
				return out
			},
		},
		{
			name: "update ca cert",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.ca_cert"),
				Item: &pb.CredentialStore{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							CaCert: wrapperspb.String(string(v2.CaCert)),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Attributes.Fields["ca_cert"] = structpb.NewStringValue(string(v2.CaCert))
				return out
			},
		},
		{
			name: "update client cert",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.client_certificate"),
				Item: &pb.CredentialStore{
					Attributes: func() *structpb.Struct {
						attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
							ClientCertificate: wrapperspb.String(string(v2.ClientCert)),
						})
						require.NoError(t, err)
						return attrs
					}(),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Attributes.Fields["client_certificate"] = structpb.NewStringValue(string(v2.ClientCert))
				return out
			},
		},
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

			if v, ok := want.Item.GetAttributes().AsMap()["token_hmac"]; ok && v.(string) == "<hmac>" {
				got.Item.Attributes.Fields["token_hmac"] = structpb.NewStringValue("<hmac>")
			}
			if v, ok := want.Item.GetAttributes().AsMap()["client_certificate_key_hmac"]; ok && v.(string) == "<hmac>" {
				got.Item.Attributes.Fields["client_certificate_key_hmac"] = structpb.NewStringValue("<hmac>")
			}

			assert.Empty(cmp.Diff(got, want, protocmp.Transform()))
		})
	}

	// cant update read only fields
	st, cleanup := freshStore()
	defer cleanup()

	roCases := []struct {
		path    string
		item    *pb.CredentialStore
		matcher func(t *testing.T, e error) // When not set defaults to checking against InvalidArgument Error
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
			path: "authorized_actions",
			item: &pb.CredentialStore{AuthorizedActions: append(testAuthorizedActions, "another")},
		},
		{
			// This fails because we do not update the vault address at the same time as
			// updating the token.
			path: "attributes.token",
			item: &pb.CredentialStore{
				Attributes: func() *structpb.Struct {
					attrs, err := handlers.ProtoToStruct(&pb.VaultCredentialStoreAttributes{
						Token: wrapperspb.String(token2),
					})
					require.NoError(t, err)
					return attrs
				}(),
			},
			matcher: func(t *testing.T, err error) {
				assert.Containsf(t, err.Error(), "cannot lookup token for updated store", "got error %v, wanted 'unable to lookup token'", err)
			},
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
			matcher := tc.matcher
			if matcher == nil {
				matcher = func(t *testing.T, e error) {
					assert.Truef(t, errors.Is(gErr, handlers.ApiErrorWithCode(codes.InvalidArgument)), "got error %v, wanted invalid argument", gErr)
				}
			}
			matcher(t, gErr)
			assert.Nil(t, got)
		})
	}
}
