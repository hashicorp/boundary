// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialstores

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/server"
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

var (
	testAuthorizedActions                = []string{"no-op", "read", "update", "delete"}
	testAuthorizedVaultCollectionActions = map[string]*structpb.ListValue{
		"credential-libraries": {
			Values: []*structpb.Value{
				structpb.NewStringValue("create"),
				structpb.NewStringValue("list"),
			},
		},
	}
	testAuthorizedStaticCollectionActions = map[string]*structpb.ListValue{
		"credentials": {
			Values: []*structpb.Value{
				structpb.NewStringValue("create"),
				structpb.NewStringValue("list"),
			},
		},
	}
)

func vaultCredentialStoreToProto(cs *vault.CredentialStore, prj *iam.Scope) *pb.CredentialStore {
	return &pb.CredentialStore{
		Id:                          cs.GetPublicId(),
		ScopeId:                     prj.GetPublicId(),
		Scope:                       &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
		CreatedTime:                 cs.GetCreateTime().GetTimestamp(),
		UpdatedTime:                 cs.GetUpdateTime().GetTimestamp(),
		Version:                     cs.GetVersion(),
		Type:                        vault.Subtype.String(),
		AuthorizedActions:           testAuthorizedActions,
		AuthorizedCollectionActions: testAuthorizedVaultCollectionActions,
		Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
			VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
				Address:                  wrapperspb.String(cs.GetVaultAddress()),
				TokenHmac:                base64.RawURLEncoding.EncodeToString(cs.Token().GetTokenHmac()),
				TokenStatus:              cs.Token().GetStatus(),
				ClientCertificate:        wrapperspb.String(string(cs.ClientCertificate().GetCertificate())),
				ClientCertificateKeyHmac: base64.RawURLEncoding.EncodeToString(cs.ClientCertificate().GetCertificateKeyHmac()),
			},
		},
	}
}

func staticCredentialStoreToProto(cs *static.CredentialStore, prj *iam.Scope) *pb.CredentialStore {
	return &pb.CredentialStore{
		Id:                          cs.GetPublicId(),
		ScopeId:                     prj.GetPublicId(),
		Scope:                       &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
		CreatedTime:                 cs.GetCreateTime().GetTimestamp(),
		UpdatedTime:                 cs.GetUpdateTime().GetTimestamp(),
		Version:                     cs.GetVersion(),
		Type:                        static.Subtype.String(),
		AuthorizedActions:           testAuthorizedActions,
		AuthorizedCollectionActions: testAuthorizedStaticCollectionActions,
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)
	err := vault.RegisterJobs(ctx, sche, rw, rw, kms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	credStoreRepoFn := func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(context.Background(), rw, rw)
	}

	_, prjNoStores := iam.TestScopes(t, iamRepo)
	_, prj := iam.TestScopes(t, iamRepo)

	var wantStores []*pb.CredentialStore
	for _, s := range vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 10) {
		wantStores = append(wantStores, vaultCredentialStoreToProto(s, prj))
	}

	for _, s := range static.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 10) {
		wantStores = append(wantStores, staticCredentialStoreToProto(s, prj))
	}

	cases := []struct {
		name    string
		req     *pbs.ListCredentialStoresRequest
		res     *pbs.ListCredentialStoresResponse
		anonRes *pbs.ListCredentialStoresResponse
		err     error
	}{
		{
			name: "List Many Stores",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId()},
			res: &pbs.ListCredentialStoresResponse{
				Items:        wantStores,
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 20,
			},
			anonRes: &pbs.ListCredentialStoresResponse{
				Items:        wantStores,
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 20,
			},
		},
		{
			name: "List No Stores",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prjNoStores.GetPublicId()},
			res: &pbs.ListCredentialStoresResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
			anonRes: &pbs.ListCredentialStoresResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
		},
		{
			name: "Filter to One Vault Store",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantStores[1].GetId())},
			res: &pbs.ListCredentialStoresResponse{
				Items:        wantStores[1:2],
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 1,
			},
			anonRes: &pbs.ListCredentialStoresResponse{
				Items:        wantStores[1:2],
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 1,
			},
		},
		{
			name: "Filter to One static Store",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantStores[11].GetId())},
			res: &pbs.ListCredentialStoresResponse{
				Items:        wantStores[11:12],
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 1,
			},
			anonRes: &pbs.ListCredentialStoresResponse{
				Items:        wantStores[11:12],
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 1,
			},
		},
		{
			name: "Filter on Attribute",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId(), Filter: fmt.Sprintf(`"/item/attributes/address"==%q`, wantStores[2].GetVaultCredentialStoreAttributes().GetAddress().Value)},
			res: &pbs.ListCredentialStoresResponse{
				Items:        wantStores[2:3],
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 1,
			},
			anonRes: &pbs.ListCredentialStoresResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			}, // anonymous user does not have access to attributes
		},
		{
			name: "Filter to No Store",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res: &pbs.ListCredentialStoresResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
			anonRes: &pbs.ListCredentialStoresResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewService(ctx, iamRepoFn, vaultRepoFn, staticRepoFn, credStoreRepoFn, 1000)
			require.NoError(t, err, "Couldn't create new host set service.")

			// Test non-anonymous listing
			got, gErr := s.ListCredentialStores(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId()), tc.req)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err), "ListCredentialStore(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(t, gErr)
			assert.Empty(t, cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				protocmp.SortRepeated(func(x, y *pb.CredentialStore) bool {
					return x.Id < y.Id
				}),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
				protocmp.IgnoreFields(&pbs.ListCredentialStoresResponse{}, "list_token"),
			))

			// Test anonymous listing
			got, gErr = s.ListCredentialStores(auth.DisabledAuthTestContext(iamRepoFn, tc.req.GetScopeId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
			require.NoError(t, gErr)
			assert.Len(t, got.Items, len(tc.anonRes.Items))
			for _, item := range got.GetItems() {
				require.Nil(t, item.CreatedTime)
				require.Nil(t, item.UpdatedTime)
				require.Zero(t, item.Version)
			}
		})
	}
}

func TestCreateVault(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)
	err := vault.RegisterJobs(ctx, sche, rw, rw, kms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	credStoreServiceFn := func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(context.Background(), rw, rw)
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

	// Ensure we're testing the OSS version of this function
	currentVaultWorkerFilterFn := validateVaultWorkerFilterFn
	validateVaultWorkerFilterFn = vaultWorkerFilterUnsupported

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
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String(newToken()),
						ClientCertificate:    wrapperspb.String(string(v.ClientCert)),
						ClientCertificateKey: wrapperspb.String(string(v.ClientKey)),
					},
				},
			}},
			idPrefix: globals.VaultCredentialStorePrefix + "_",
			wantErr:  true,
		},
		{
			name: "Bad token",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String("madeup"),
						CaCert:               wrapperspb.String(string(v.CaCert)),
						ClientCertificate:    wrapperspb.String(string(v.ClientCert)),
						ClientCertificateKey: wrapperspb.String(string(v.ClientKey)),
					},
				},
			}},
			idPrefix: globals.VaultCredentialStorePrefix + "_",
			wantErr:  true,
		},
		{
			name: "Define only client cert",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:           wrapperspb.String(v.Addr),
						Token:             wrapperspb.String(newToken()),
						CaCert:            wrapperspb.String(string(v.CaCert)),
						ClientCertificate: wrapperspb.String(string(v.ClientCert)),
					},
				},
			}},
			idPrefix: globals.VaultCredentialStorePrefix + "_",
			err:      handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Define only client cert key",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String(newToken()),
						CaCert:               wrapperspb.String(string(v.CaCert)),
						ClientCertificateKey: wrapperspb.String(string(v.ClientKey)),
					},
				},
			}},
			idPrefix: globals.VaultCredentialStorePrefix + "_",
			err:      handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Define key in both client cert payload and key field",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String(newToken()),
						CaCert:               wrapperspb.String(string(v.CaCert)),
						ClientCertificateKey: wrapperspb.String(string(append(v.ClientCert, v.ClientKey...))),
						ClientCertificate:    wrapperspb.String(string(v.ClientKey)),
					},
				},
			}},
			idPrefix: globals.VaultCredentialStorePrefix + "_",
			err:      handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Id:      globals.VaultCredentialStorePrefix + "_notallowed",
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
					},
				},
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
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
					},
				},
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
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify worker filter",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:           wrapperspb.String(v.Addr),
						Token:             wrapperspb.String(newToken()),
						CaCert:            wrapperspb.String(string(v.CaCert)),
						ClientCertificate: wrapperspb.String(string(v.ClientCert) + string(v.ClientKey)),
						WorkerFilter:      wrapperspb.String(`"worker" in "/tags/name"`),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify type",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
						Token:   wrapperspb.String(newToken()),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify vault VaultAddress",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Token: wrapperspb.String(newToken()),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify vault token",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address: wrapperspb.String(v.Addr),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create a valid vault CredentialStore with client cert and key in same field",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:           wrapperspb.String(v.Addr),
						Token:             wrapperspb.String(newToken()),
						CaCert:            wrapperspb.String(string(v.CaCert)),
						ClientCertificate: wrapperspb.String(string(v.ClientCert) + string(v.ClientKey)),
					},
				},
			}},
			idPrefix: globals.VaultCredentialStorePrefix + "_",
			res: &pbs.CreateCredentialStoreResponse{
				Uri: fmt.Sprintf("credential-stores/%s_", globals.VaultCredentialStorePrefix),
				Item: &pb.CredentialStore{
					ScopeId: prj.GetPublicId(),
					Scope:   &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version: 1,
					Type:    vault.Subtype.String(),
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							CaCert:                   wrapperspb.String(string(v.CaCert)),
							Address:                  wrapperspb.String(v.Addr),
							TokenHmac:                "<hmac>",
							TokenStatus:              "current",
							ClientCertificate:        wrapperspb.String(string(v.ClientCert)),
							ClientCertificateKeyHmac: "<hmac>",
						},
					},
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: testAuthorizedVaultCollectionActions,
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
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address:              wrapperspb.String(v.Addr),
						Token:                wrapperspb.String(newToken()),
						CaCert:               wrapperspb.String(string(v.CaCert)),
						ClientCertificate:    wrapperspb.String(string(v.ClientCert)),
						ClientCertificateKey: wrapperspb.String(string(v.ClientKey)),
					},
				},
			}},
			idPrefix: globals.VaultCredentialStorePrefix + "_",
			res: &pbs.CreateCredentialStoreResponse{
				Uri: fmt.Sprintf("credential-stores/%s_", globals.VaultCredentialStorePrefix),
				Item: &pb.CredentialStore{
					ScopeId:     prj.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Scope:       &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:     1,
					Type:        vault.Subtype.String(),
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							CaCert:                   wrapperspb.String(string(v.CaCert)),
							Address:                  wrapperspb.String(v.Addr),
							TokenHmac:                "<hmac>",
							TokenStatus:              "current",
							ClientCertificate:        wrapperspb.String(string(v.ClientCert)),
							ClientCertificateKeyHmac: "<hmac>",
						},
					},
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: testAuthorizedVaultCollectionActions,
				},
			},
		},
		{
			name: "Create a valid vault CredentialStore IPv6 Address",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "name-ipv6"},
				Description: &wrapperspb.StringValue{Value: "desc-ipv6"},
				Type:        vault.Subtype.String(),
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Address: func() *wrapperspb.StringValue {
							u, err := url.Parse(v.Addr)
							require.NoError(t, err)
							require.NotNil(t, u)
							require.NotEmpty(t, u.Port())
							require.NotEmpty(t, u.Scheme)

							return wrapperspb.String(fmt.Sprintf("%s://[0000:0000:0000:0000:0000:0000:0000:0001]:%s", u.Scheme, u.Port()))
						}(),
						Token:                wrapperspb.String(newToken()),
						CaCert:               wrapperspb.String(string(v.CaCert)),
						ClientCertificate:    wrapperspb.String(string(v.ClientCert)),
						ClientCertificateKey: wrapperspb.String(string(v.ClientKey)),
					},
				},
			}},
			idPrefix: globals.VaultCredentialStorePrefix + "_",
			res: &pbs.CreateCredentialStoreResponse{
				Uri: fmt.Sprintf("credential-stores/%s_", globals.VaultCredentialStorePrefix),
				Item: &pb.CredentialStore{
					ScopeId:     prj.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "name-ipv6"},
					Description: &wrapperspb.StringValue{Value: "desc-ipv6"},
					Scope:       &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:     1,
					Type:        vault.Subtype.String(),
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							CaCert: wrapperspb.String(string(v.CaCert)),
							Address: func() *wrapperspb.StringValue {
								u, err := url.Parse(v.Addr)
								require.NoError(t, err)
								require.NotNil(t, u)
								require.NotEmpty(t, u.Port())
								require.NotEmpty(t, u.Scheme)

								return wrapperspb.String(fmt.Sprintf("%s://[::1]:%s", u.Scheme, u.Port()))
							}(),
							TokenHmac:                "<hmac>",
							TokenStatus:              "current",
							ClientCertificate:        wrapperspb.String(string(v.ClientCert)),
							ClientCertificateKeyHmac: "<hmac>",
						},
					},
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: testAuthorizedVaultCollectionActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := NewService(ctx, iamRepoFn, vaultRepoFn, staticRepoFn, credStoreServiceFn, 1000)
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
			cmpOptions := []cmp.Option{
				protocmp.Transform(),
				protocmp.SortRepeatedFields(got),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pbs.CreateCredentialStoreResponse{}, "uri"))

				assert.True(strings.HasPrefix(got.GetItem().GetId(), tc.idPrefix))
				cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pb.CredentialStore{}, "id"))

				gotCreateTime := got.GetItem().GetCreatedTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime()

				// Verify it is a credential store created after the test setup's default credential store
				assert.True(gotCreateTime.AsTime().After(defaultCreated.AsTime()), "New credential store should have been created after default credential store. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.AsTime().After(defaultCreated.AsTime()), "New credential store should have been updated after default credential store. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)
				cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pb.CredentialStore{}, "created_time"))
				cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pb.CredentialStore{}, "updated_time"))

				if got.Item.GetVaultCredentialStoreAttributes().TokenHmac != "" {
					assert.NotEqual(tc.req.Item.GetVaultCredentialStoreAttributes().Token, got.Item.GetVaultCredentialStoreAttributes().TokenHmac)
					cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pb.VaultCredentialStoreAttributes{}, "token_hmac"))
				}
				if got.Item.GetVaultCredentialStoreAttributes().ClientCertificateKeyHmac != "" {
					assert.NotEqual(tc.req.Item.GetVaultCredentialStoreAttributes().ClientCertificateKeyHmac, got.Item.GetVaultCredentialStoreAttributes().ClientCertificateKeyHmac)
					cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pb.VaultCredentialStoreAttributes{}, "client_certificate_key_hmac"))
				}
			}
			assert.Empty(cmp.Diff(got, tc.res, cmpOptions...), "CreateCredentialStore(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
	// Reset VaultWorkerFilterFn
	validateVaultWorkerFilterFn = currentVaultWorkerFilterFn
}

func TestCreateStatic(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	credStoreServiceFn := func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(context.Background(), rw, rw)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	defaultCreated := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	cleanup := func(s Service) {
		ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())
		r, err := s.ListCredentialStores(ctx, &pbs.ListCredentialStoresRequest{ScopeId: prj.GetPublicId()})
		require.NoError(t, err)
		for _, i := range r.GetItems() {
			_, err := s.DeleteCredentialStore(ctx, &pbs.DeleteCredentialStoreRequest{Id: i.GetId()})
			require.NoError(t, err)
		}
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
			name: "Can't specify Id",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Id:      globals.StaticCredentialStorePrefix + "_notallowed",
				Type:    static.Subtype.String(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				CreatedTime: timestamppb.Now(),
				Type:        static.Subtype.String(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				UpdatedTime: timestamppb.Now(),
				Type:        static.Subtype.String(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must specify type",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Create a valid static CredentialStore",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId: prj.GetPublicId(),
				Type:    static.Subtype.String(),
			}},
			idPrefix: globals.StaticCredentialStorePrefix + "_",
			res: &pbs.CreateCredentialStoreResponse{
				Uri: fmt.Sprintf("credential-stores/%s_", globals.StaticCredentialStorePrefix),
				Item: &pb.CredentialStore{
					ScopeId:                     prj.GetPublicId(),
					Scope:                       &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:                     1,
					Type:                        static.Subtype.String(),
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: testAuthorizedStaticCollectionActions,
				},
			},
		},
		{
			name: "Create a valid static CredentialStore with name and description",
			req: &pbs.CreateCredentialStoreRequest{Item: &pb.CredentialStore{
				ScopeId:     prj.GetPublicId(),
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
				Type:        static.Subtype.String(),
			}},
			idPrefix: globals.StaticCredentialStorePrefix + "_",
			res: &pbs.CreateCredentialStoreResponse{
				Uri: fmt.Sprintf("credential-stores/%s_", globals.StaticCredentialStorePrefix),
				Item: &pb.CredentialStore{
					ScopeId:                     prj.GetPublicId(),
					Scope:                       &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:                     1,
					Type:                        static.Subtype.String(),
					AuthorizedActions:           testAuthorizedActions,
					Name:                        &wrapperspb.StringValue{Value: "name"},
					Description:                 &wrapperspb.StringValue{Value: "desc"},
					AuthorizedCollectionActions: testAuthorizedStaticCollectionActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := NewService(ctx, iamRepoFn, vaultRepoFn, staticRepoFn, credStoreServiceFn, 1000)
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
			cmpOptions := []cmp.Option{
				protocmp.Transform(),
				protocmp.SortRepeatedFields(got),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			}
			if got != nil {
				assert.Contains(got.GetUri(), tc.res.Uri)
				cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pbs.CreateCredentialStoreResponse{}, "uri"))

				assert.True(strings.HasPrefix(got.GetItem().GetId(), tc.idPrefix))
				cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pb.CredentialStore{}, "id"))

				gotCreateTime := got.GetItem().GetCreatedTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime()

				// Verify it is a credential store created after the test setup's default credential store
				assert.True(gotCreateTime.AsTime().After(defaultCreated.CreateTime.AsTime()), "New credential store should have been created after default credential store. Was created %v, which is after %v", gotCreateTime, defaultCreated)
				assert.True(gotUpdateTime.AsTime().After(defaultCreated.CreateTime.AsTime()), "New credential store should have been updated after default credential store. Was updated %v, which is after %v", gotUpdateTime, defaultCreated)
				cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pb.CredentialStore{}, "created_time"))
				cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pb.CredentialStore{}, "updated_time"))
			}
			assert.Empty(cmp.Diff(got, tc.res, cmpOptions...), "CreateCredentialStore(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	credStoreServiceFn := func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(context.Background(), rw, rw)
	}

	_, prj := iam.TestScopes(t, iamRepo)

	vaultStore := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	staticStore := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	staticStorePrev := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId(), static.WithPublicId(fmt.Sprintf("%s_1234567890", globals.StaticCredentialStorePreviousPrefix)))
	s, err := NewService(ctx, iamRepoFn, vaultRepoFn, staticRepoFn, credStoreServiceFn, 1000)
	require.NoError(t, err)

	cases := []struct {
		name string
		id   string
		res  *pbs.GetCredentialStoreResponse
		err  error
	}{
		{
			name: "vault success",
			id:   vaultStore.GetPublicId(),
			res: &pbs.GetCredentialStoreResponse{
				Item: &pb.CredentialStore{
					Id:                          vaultStore.GetPublicId(),
					ScopeId:                     vaultStore.GetProjectId(),
					Scope:                       &scopepb.ScopeInfo{Id: vaultStore.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:                        vault.Subtype.String(),
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: testAuthorizedVaultCollectionActions,
					CreatedTime:                 vaultStore.CreateTime.GetTimestamp(),
					UpdatedTime:                 vaultStore.UpdateTime.GetTimestamp(),
					Version:                     1,
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							Address:                  wrapperspb.String(vaultStore.GetVaultAddress()),
							TokenHmac:                base64.RawURLEncoding.EncodeToString(vaultStore.Token().GetTokenHmac()),
							TokenStatus:              vaultStore.Token().GetStatus(),
							ClientCertificate:        wrapperspb.String(string(vaultStore.ClientCertificate().GetCertificate())),
							ClientCertificateKeyHmac: base64.RawURLEncoding.EncodeToString(vaultStore.ClientCertificate().GetCertificateKeyHmac()),
						},
					},
				},
			},
		},
		{
			name: "static success",
			id:   staticStore.GetPublicId(),
			res: &pbs.GetCredentialStoreResponse{
				Item: &pb.CredentialStore{
					Id:                          staticStore.GetPublicId(),
					ScopeId:                     staticStore.GetProjectId(),
					Scope:                       &scopepb.ScopeInfo{Id: staticStore.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:                        static.Subtype.String(),
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: testAuthorizedStaticCollectionActions,
					CreatedTime:                 staticStore.CreateTime.GetTimestamp(),
					UpdatedTime:                 staticStore.UpdateTime.GetTimestamp(),
					Version:                     1,
				},
			},
		},
		{
			name: "static prev prefix success",
			id:   staticStorePrev.GetPublicId(),
			res: &pbs.GetCredentialStoreResponse{
				Item: &pb.CredentialStore{
					Id:                          staticStorePrev.GetPublicId(),
					ScopeId:                     staticStorePrev.GetProjectId(),
					Scope:                       &scopepb.ScopeInfo{Id: staticStorePrev.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:                        static.Subtype.String(),
					AuthorizedActions:           testAuthorizedActions,
					AuthorizedCollectionActions: testAuthorizedStaticCollectionActions,
					CreatedTime:                 staticStorePrev.CreateTime.GetTimestamp(),
					UpdatedTime:                 staticStorePrev.UpdateTime.GetTimestamp(),
					Version:                     1,
				},
			},
		},
		{
			name: "vault not found error",
			id:   fmt.Sprintf("%s_1234567890", globals.VaultCredentialStorePrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "static not found error",
			id:   fmt.Sprintf("%s_1234567890", globals.StaticCredentialStorePrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", globals.StaticHostPrefix),
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
			assert.Empty(t, cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			))

			// Test anonymous get
			got, gErr = s.GetCredentialStore(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), req)
			require.NoError(t, gErr)
			require.Nil(t, got.Item.CreatedTime)
			require.Nil(t, got.Item.UpdatedTime)
			require.Zero(t, got.Item.Version)
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)
	err := vault.RegisterJobs(context.Background(), sche, rw, rw, kms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	credStoreServiceFn := func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(context.Background(), rw, rw)
	}

	_, prj := iam.TestScopes(t, iamRepo)

	vaultStore := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 2)[0]
	staticStore := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	s, err := NewService(ctx, iamRepoFn, vaultRepoFn, staticRepoFn, credStoreServiceFn, 1000)
	require.NoError(t, err)

	cases := []struct {
		name string
		id   string
		err  error
		res  *pbs.DeleteCredentialStoreResponse
	}{
		{
			name: "vault success",
			id:   vaultStore.GetPublicId(),
		},
		{
			name: "static success",
			id:   staticStore.GetPublicId(),
		},
		{
			name: "vault not found error",
			id:   fmt.Sprintf("%s_1234567890", globals.VaultCredentialStorePrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "static not found error",
			id:   fmt.Sprintf("%s_1234567890", globals.StaticCredentialStorePrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", globals.StaticHostPrefix),
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gErr := s.DeleteCredentialStore(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), &pbs.DeleteCredentialStoreRequest{Id: tc.id})
			assert.EqualValuesf(t, tc.res, got, "DeleteCredentialStore got response %q, wanted %q", got, tc.res)
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

func TestUpdateVault(t *testing.T) {
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)
	err := vault.RegisterJobs(testCtx, sche, rw, rw, kms)
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(testCtx, rw, rw, kms, sche)
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(testCtx, rw, rw, kms)
	}
	credStoreServiceFn := func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(context.Background(), rw, rw)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())

	s, err := NewService(ctx, iamRepoFn, vaultRepoFn, staticRepoFn, credStoreServiceFn, 1000)
	require.NoError(t, err)

	fieldmask := func(paths ...string) *fieldmaskpb.FieldMask {
		return &fieldmaskpb.FieldMask{Paths: paths}
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	v := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestClientTLS), vault.WithClientKey(key))
	_, token1b := v.CreateToken(t)
	clientCert, err := vault.NewClientCertificate(ctx, v.ClientCert, v.ClientKey)
	require.NoError(t, err)

	v2 := vault.NewTestVaultServer(t, vault.WithTestVaultTLS(vault.TestClientTLS), vault.WithClientKey(key))
	_, token2 := v2.CreateToken(t)
	clientCert2, err := vault.NewClientCertificate(ctx, v2.ClientCert, v2.ClientKey)
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
				UpdateMask: fieldmask(globals.AttributesAddressField, "attributes.client_certificate", "attributes.client_certificate_key", "attributes.ca_cert", "attributes.token"),
				Item: &pb.CredentialStore{
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							Address:              wrapperspb.String(v2.Addr),
							Token:                wrapperspb.String(token2),
							ClientCertificate:    wrapperspb.String(string(clientCert2.Certificate)),
							ClientCertificateKey: wrapperspb.String(string(clientCert2.CertificateKey)),
							CaCert:               wrapperspb.String(string(v2.CaCert)),
						},
					},
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.GetVaultCredentialStoreAttributes().Address = wrapperspb.String(v2.Addr)
				out.GetVaultCredentialStoreAttributes().ClientCertificate = wrapperspb.String(string(clientCert2.Certificate))
				out.GetVaultCredentialStoreAttributes().CaCert = wrapperspb.String(string(v2.CaCert))
				out.GetVaultCredentialStoreAttributes().TokenHmac = "<hmac>"
				out.GetVaultCredentialStoreAttributes().ClientCertificateKeyHmac = "<hmac>"
				return out
			},
		},
		{
			name: "update token",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.token"),
				Item: &pb.CredentialStore{
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							Token: wrapperspb.String(token1b),
						},
					},
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.GetVaultCredentialStoreAttributes().TokenHmac = "<hmac>"
				out.GetVaultCredentialStoreAttributes().TokenStatus = "current"
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
				out.GetVaultCredentialStoreAttributes().ClientCertificate = nil
				out.GetVaultCredentialStoreAttributes().ClientCertificateKeyHmac = ""
				return out
			},
		},
		{
			name: "update namespace",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.namespace"),
				Item: &pb.CredentialStore{
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							Namespace: wrapperspb.String("update namespace"),
						},
					},
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.GetVaultCredentialStoreAttributes().Namespace = wrapperspb.String("update namespace")
				return out
			},
		},
		{
			name: "update tls server name",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.tls_server_name"),
				Item: &pb.CredentialStore{
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							TlsServerName: wrapperspb.String("UpdateTlsServerName"),
						},
					},
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.GetVaultCredentialStoreAttributes().TlsServerName = wrapperspb.String("UpdateTlsServerName")
				return out
			},
		},
		{
			name: "update TlsSkipVerify",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.tls_skip_verify"),
				Item: &pb.CredentialStore{
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							TlsSkipVerify: wrapperspb.Bool(true),
						},
					},
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.GetVaultCredentialStoreAttributes().TlsSkipVerify = wrapperspb.Bool(true)
				return out
			},
		},
		{
			name: "update ca cert",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.ca_cert"),
				Item: &pb.CredentialStore{
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							CaCert: wrapperspb.String(string(v2.CaCert)),
						},
					},
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.GetVaultCredentialStoreAttributes().CaCert = wrapperspb.String(string(v2.CaCert))
				return out
			},
		},
		{
			name: "update client cert",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("attributes.client_certificate"),
				Item: &pb.CredentialStore{
					Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
						VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
							ClientCertificate: wrapperspb.String(string(v2.ClientCert)),
						},
					},
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.GetVaultCredentialStoreAttributes().ClientCertificate = wrapperspb.String(string(v2.ClientCert))
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

			if want.Item.GetVaultCredentialStoreAttributes().TokenHmac == "<hmac>" {
				got.Item.GetVaultCredentialStoreAttributes().TokenHmac = "<hmac>"
			}
			if want.Item.GetVaultCredentialStoreAttributes().ClientCertificateKeyHmac == "<hmac>" {
				got.Item.GetVaultCredentialStoreAttributes().ClientCertificateKeyHmac = "<hmac>"
			}

			assert.Empty(cmp.Diff(
				got,
				want,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			))
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
				Attrs: &pb.CredentialStore_VaultCredentialStoreAttributes{
					VaultCredentialStoreAttributes: &pb.VaultCredentialStoreAttributes{
						Token: wrapperspb.String(token2),
					},
				},
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

func TestUpdateStatic(t *testing.T) {
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(testCtx, rw, rw, kms, sche)
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(testCtx, rw, rw, kms)
	}
	credStoreServiceFn := func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(context.Background(), rw, rw)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())

	s, err := NewService(ctx, iamRepoFn, vaultRepoFn, staticRepoFn, credStoreServiceFn, 1000)
	require.NoError(t, err)

	fieldmask := func(paths ...string) *fieldmaskpb.FieldMask {
		return &fieldmaskpb.FieldMask{Paths: paths}
	}

	freshStore := func() (*static.CredentialStore, func()) {
		t.Helper()
		st := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
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
			name: "name",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("name"),
				Item: &pb.CredentialStore{
					Name: wrapperspb.String("new-name"),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Name = wrapperspb.String("new-name")
				return out
			},
		},
		{
			name: "description",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("description"),
				Item: &pb.CredentialStore{
					Description: wrapperspb.String("new-description"),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Description = wrapperspb.String("new-description")
				return out
			},
		},
		{
			name: "name-and-description",
			req: &pbs.UpdateCredentialStoreRequest{
				UpdateMask: fieldmask("name", "description"),
				Item: &pb.CredentialStore{
					Name:        wrapperspb.String("new-name"),
					Description: wrapperspb.String("new-description"),
				},
			},
			res: func(in *pb.CredentialStore) *pb.CredentialStore {
				out := proto.Clone(in).(*pb.CredentialStore)
				out.Name = wrapperspb.String("new-name")
				out.Description = wrapperspb.String("new-description")
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

			assert.Empty(cmp.Diff(
				got,
				want,
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			))
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

func TestListPagination(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDB, err := conn.SqlDB(ctx)
	require.NoError(err)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	vaultRepoFn := func() (*vault.Repository, error) {
		return vault.NewRepository(ctx, rw, rw, kms, sche)
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kms)
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}
	credStoreServiceFn := func() (*credential.StoreRepository, error) {
		return credential.NewStoreRepository(context.Background(), rw, rw)
	}
	staticRepo, err := staticRepoFn()
	require.NoError(err)
	tokenRepo, err := tokenRepoFn()
	require.NoError(err)

	_, prjNoStores := iam.TestScopes(t, iamRepo)
	o, prj := iam.TestScopes(t, iamRepo)

	var allCredentialStores []*pb.CredentialStore
	for _, l := range static.TestCredentialStores(t, conn, wrapper, prj.PublicId, 5) {
		allCredentialStores = append(allCredentialStores, staticCredentialStoreToProto(l, prj))
	}
	for _, l := range vault.TestCredentialStores(t, conn, wrapper, prj.PublicId, 5) {
		allCredentialStores = append(allCredentialStores, vaultCredentialStoreToProto(l, prj))
	}

	// Reverse slice since we're sorting by create time descending
	slices.Reverse(allCredentialStores)

	// Run analyze to update postgres meta tables
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(err)

	authMethod := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "test_user")
	u := iam.TestUser(t, iamRepo, o.GetPublicId(), iam.WithAccountIds(acct.PublicId))
	role1 := iam.TestRole(t, conn, prj.GetPublicId())
	iam.TestRoleGrant(t, conn, role1.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, role1.GetPublicId(), u.GetPublicId())
	role2 := iam.TestRole(t, conn, prjNoStores.GetPublicId())
	iam.TestRoleGrant(t, conn, role2.GetPublicId(), "ids=*;type=*;actions=*")
	iam.TestUserRole(t, conn, role2.GetPublicId(), u.GetPublicId())
	at, err := tokenRepo.CreateAuthToken(ctx, u, acct.GetPublicId())
	require.NoError(err)

	// Test without anon user
	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	s, err := NewService(ctx, iamRepoFn, vaultRepoFn, staticRepoFn, credStoreServiceFn, 1000)
	require.NoError(err)

	// Start paginating, recursively
	req := &pbs.ListCredentialStoresRequest{
		ScopeId:   prj.PublicId,
		Filter:    "",
		ListToken: "",
		PageSize:  2,
	}
	got, err := s.ListCredentialStores(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 2)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialStoresResponse{
				Items:        allCredentialStores[0:2],
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialStoresResponse{}, "list_token"),
		),
	)

	// Request second page
	req.ListToken = got.ListToken
	got, err = s.ListCredentialStores(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 2)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialStoresResponse{
				Items:        allCredentialStores[2:4],
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialStoresResponse{}, "list_token"),
		),
	)

	// Request rest of results
	req.ListToken = got.ListToken
	req.PageSize = 10
	got, err = s.ListCredentialStores(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 6)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialStoresResponse{
				Items:        allCredentialStores[4:],
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialStoresResponse{}, "list_token"),
		),
	)

	// Create another credential store
	newCredStore := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	pbNewCredStore := staticCredentialStoreToProto(newCredStore, prj)
	// Add to the front since it's most recently updated
	allCredentialStores = append([]*pb.CredentialStore{pbNewCredStore}, allCredentialStores...)

	// Delete one of the other credential stores
	_, err = staticRepo.DeleteCredentialStore(ctx, allCredentialStores[len(allCredentialStores)-1].Id)
	require.NoError(err)
	deletedCredStore := allCredentialStores[len(allCredentialStores)-1]
	allCredentialStores = allCredentialStores[:len(allCredentialStores)-1]

	// Update one of the other stores
	allCredentialStores[len(allCredentialStores)-1].Name = wrapperspb.String("new-name")
	allCredentialStores[len(allCredentialStores)-1].Version = 2
	updatedStore := &static.CredentialStore{
		CredentialStore: &store.CredentialStore{
			PublicId:  allCredentialStores[len(allCredentialStores)-1].GetId(),
			Name:      allCredentialStores[len(allCredentialStores)-1].GetName().GetValue(),
			ProjectId: allCredentialStores[len(allCredentialStores)-1].GetScopeId(),
		},
	}
	stre, _, err := staticRepo.UpdateCredentialStore(ctx, updatedStore, 1, []string{"name"})
	require.NoError(err)
	allCredentialStores[len(allCredentialStores)-1].UpdatedTime = stre.CredentialStore.UpdateTime.GetTimestamp()
	allCredentialStores[len(allCredentialStores)-1].Version = stre.GetVersion()
	// Add to the front since it's most recently updated
	allCredentialStores = append(
		[]*pb.CredentialStore{allCredentialStores[len(allCredentialStores)-1]},
		allCredentialStores[:len(allCredentialStores)-1]...,
	)

	// Run analyze to update postgres meta tables
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(err)

	// Request updated results
	req.ListToken = got.ListToken
	req.PageSize = 1
	got, err = s.ListCredentialStores(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialStoresResponse{
				Items:        []*pb.CredentialStore{allCredentialStores[0]},
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "updated_time",
				SortDir:      "desc",
				// Should contain the deleted session
				RemovedIds:   []string{deletedCredStore.Id},
				EstItemCount: 10,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialStoresResponse{}, "list_token"),
		),
	)
	// Get next page
	req.ListToken = got.ListToken
	got, err = s.ListCredentialStores(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialStoresResponse{
				Items:        []*pb.CredentialStore{allCredentialStores[1]},
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialStoresResponse{}, "list_token"),
		),
	)

	// Request new page with filter requiring looping
	// to fill the page.
	req.ListToken = ""
	req.PageSize = 1
	req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, allCredentialStores[len(allCredentialStores)-2].Id, allCredentialStores[len(allCredentialStores)-1].Id)
	got, err = s.ListCredentialStores(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialStoresResponse{
				Items:        []*pb.CredentialStore{allCredentialStores[len(allCredentialStores)-2]},
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				// Should be empty again
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialStoresResponse{}, "list_token"),
		),
	)
	req.ListToken = got.ListToken
	// Get the second page
	got, err = s.ListCredentialStores(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialStoresResponse{
				Items:        []*pb.CredentialStore{allCredentialStores[len(allCredentialStores)-1]},
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 10,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialStoresResponse{}, "list_token"),
		),
	)
	req.ListToken = got.ListToken

	// List items in the empty scope
	req = &pbs.ListCredentialStoresRequest{
		ScopeId:   prjNoStores.PublicId,
		Filter:    "",
		ListToken: "",
		PageSize:  2,
	}
	got, err = s.ListCredentialStores(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 0)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialStoresResponse{
				Items:        nil,
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			cmpopts.SortSlices(func(a, b protocmp.Message) bool {
				return a.String() < b.String()
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialStoresResponse{}, "list_token"),
		),
	)

	// Create unauthenticated user
	unauthAt := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	unauthR := iam.TestRole(t, conn, prj.GetPublicId())
	_ = iam.TestUserRole(t, conn, unauthR.GetPublicId(), unauthAt.GetIamUserId())

	// Make a request with the unauthenticated user,
	// ensure the response is 403 forbidden.
	requestInfo = authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    unauthAt.GetPublicId(),
		Token:       unauthAt.GetToken(),
	}
	requestContext = context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	_, err = s.ListCredentialStores(ctx, &pbs.ListCredentialStoresRequest{
		ScopeId:   "global",
		Recursive: true,
	})
	require.Error(err)
	assert.ErrorIs(handlers.ForbiddenError(), err)
}
