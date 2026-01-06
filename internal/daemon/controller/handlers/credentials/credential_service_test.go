// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentials"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/testdata"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete"}

func staticJsonCredentialToProto(cred *static.JsonCredential, prj *iam.Scope, hmac string) *pb.Credential {
	return &pb.Credential{
		Id:                cred.GetPublicId(),
		CredentialStoreId: cred.GetStoreId(),
		Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
		CreatedTime:       cred.GetCreateTime().GetTimestamp(),
		UpdatedTime:       cred.GetUpdateTime().GetTimestamp(),
		Version:           cred.GetVersion(),
		Type:              credential.JsonSubtype.String(),
		AuthorizedActions: testAuthorizedActions,
		Attrs: &pb.Credential_JsonAttributes{
			JsonAttributes: &pb.JsonAttributes{
				ObjectHmac: base64.RawURLEncoding.EncodeToString([]byte(hmac)),
			},
		},
	}
}

func staticUsernamePasswordCredentialToProto(cred *static.UsernamePasswordCredential, prj *iam.Scope, hmac string) *pb.Credential {
	return &pb.Credential{
		Id:                cred.GetPublicId(),
		CredentialStoreId: cred.GetStoreId(),
		Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
		CreatedTime:       cred.GetCreateTime().GetTimestamp(),
		UpdatedTime:       cred.GetUpdateTime().GetTimestamp(),
		Version:           cred.GetVersion(),
		Type:              credential.UsernamePasswordSubtype.String(),
		AuthorizedActions: testAuthorizedActions,
		Attrs: &pb.Credential_UsernamePasswordAttributes{
			UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
				Username:     wrapperspb.String(cred.GetUsername()),
				PasswordHmac: base64.RawURLEncoding.EncodeToString([]byte(hmac)),
			},
		},
	}
}

func staticPasswordCredentialToProto(cred *static.PasswordCredential, prj *iam.Scope, hmac string) *pb.Credential {
	return &pb.Credential{
		Id:                cred.GetPublicId(),
		CredentialStoreId: cred.GetStoreId(),
		Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
		CreatedTime:       cred.GetCreateTime().GetTimestamp(),
		UpdatedTime:       cred.GetUpdateTime().GetTimestamp(),
		Version:           cred.GetVersion(),
		Type:              credential.PasswordSubtype.String(),
		AuthorizedActions: testAuthorizedActions,
		Attrs: &pb.Credential_PasswordAttributes{
			PasswordAttributes: &pb.PasswordAttributes{
				PasswordHmac: base64.RawURLEncoding.EncodeToString([]byte(hmac)),
			},
		},
	}
}

func staticUsernamePasswordDomainCredentialToProto(cred *static.UsernamePasswordDomainCredential, prj *iam.Scope, hmac string) *pb.Credential {
	return &pb.Credential{
		Id:                cred.GetPublicId(),
		CredentialStoreId: cred.GetStoreId(),
		Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
		CreatedTime:       cred.GetCreateTime().GetTimestamp(),
		UpdatedTime:       cred.GetUpdateTime().GetTimestamp(),
		Version:           cred.GetVersion(),
		Type:              credential.UsernamePasswordDomainSubtype.String(),
		AuthorizedActions: testAuthorizedActions,
		Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
			UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
				Username:     wrapperspb.String(cred.GetUsername()),
				PasswordHmac: base64.RawURLEncoding.EncodeToString([]byte(hmac)),
				Domain:       wrapperspb.String(cred.GetDomain()),
			},
		},
	}
}

func staticSshCredentialToProto(cred *static.SshPrivateKeyCredential, prj *iam.Scope, hmac string) *pb.Credential {
	return &pb.Credential{
		Id:                cred.GetPublicId(),
		CredentialStoreId: cred.GetStoreId(),
		Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
		CreatedTime:       cred.GetCreateTime().GetTimestamp(),
		UpdatedTime:       cred.GetUpdateTime().GetTimestamp(),
		Version:           cred.GetVersion(),
		Type:              credential.SshPrivateKeySubtype.String(),
		AuthorizedActions: testAuthorizedActions,
		Attrs: &pb.Credential_SshPrivateKeyAttributes{
			SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
				Username:       wrapperspb.String(cred.GetUsername()),
				PrivateKeyHmac: base64.RawURLEncoding.EncodeToString([]byte(hmac)),
			},
		},
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kkms)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	store := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	storeNoCreds := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	databaseWrapper, err := kkms.GetWrapper(ctx, prj.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)

	var wantCreds []*pb.Credential
	for i := 0; i < 10; i++ {
		user := fmt.Sprintf("user-%d", i)
		pass := fmt.Sprintf("pass-%d", i)
		c := static.TestUsernamePasswordCredential(t, conn, wrapper, user, pass, store.GetPublicId(), prj.GetPublicId())
		hm, err := crypto.HmacSha256(ctx, []byte(pass), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
		require.NoError(t, err)
		wantCreds = append(wantCreds, staticUsernamePasswordCredentialToProto(c, prj, hm))

		domain := fmt.Sprintf("domain-%d", i)
		upd := static.TestUsernamePasswordDomainCredential(t, conn, wrapper, user, pass, domain, store.GetPublicId(), prj.GetPublicId())
		hm, err = crypto.HmacSha256(ctx, []byte(pass), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
		require.NoError(t, err)
		wantCreds = append(wantCreds, staticUsernamePasswordDomainCredentialToProto(upd, prj, hm))

		p := static.TestPasswordCredential(t, conn, wrapper, pass, store.GetPublicId(), prj.GetPublicId())
		hm, err = crypto.HmacSha256(ctx, []byte(pass), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
		require.NoError(t, err)
		wantCreds = append(wantCreds, staticPasswordCredentialToProto(p, prj, hm))

		spk := static.TestSshPrivateKeyCredential(t, conn, wrapper, user, static.TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId())
		hm, err = crypto.HmacSha256(ctx, []byte(static.TestSshPrivateKeyPem), databaseWrapper, []byte(store.GetPublicId()), nil)
		require.NoError(t, err)
		wantCreds = append(wantCreds, staticSshCredentialToProto(spk, prj, hm))

		obj, objBytes := static.TestJsonObject(t)

		credJson := static.TestJsonCredential(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj)
		hm, err = crypto.HmacSha256(ctx, objBytes, databaseWrapper, []byte(store.GetPublicId()), nil)
		require.NoError(t, err)
		wantCreds = append(wantCreds, staticJsonCredentialToProto(credJson, prj, hm))
	}

	cases := []struct {
		name    string
		req     *pbs.ListCredentialsRequest
		res     *pbs.ListCredentialsResponse
		anonRes *pbs.ListCredentialsResponse
		err     error
	}{
		{
			name: "List many credentials",
			req:  &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId()},
			res: &pbs.ListCredentialsResponse{
				Items:        wantCreds,
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 50,
			},
			anonRes: &pbs.ListCredentialsResponse{
				Items:        wantCreds,
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 30,
			},
		},
		{
			name: "List no credentials",
			req:  &pbs.ListCredentialsRequest{CredentialStoreId: storeNoCreds.GetPublicId()},
			res: &pbs.ListCredentialsResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
			anonRes: &pbs.ListCredentialsResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
		},
		{
			name: "Filter to one credential",
			req:  &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantCreds[1].GetId())},
			res: &pbs.ListCredentialsResponse{
				Items:        wantCreds[1:2],
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 1,
			},
			anonRes: &pbs.ListCredentialsResponse{
				Items:        wantCreds[1:2],
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
			req:  &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId(), Filter: fmt.Sprintf(`"/item/attributes/username"==%q`, wantCreds[0].GetUsernamePasswordAttributes().GetUsername().Value)},
			res: &pbs.ListCredentialsResponse{
				Items:        []*pb.Credential{wantCreds[0], wantCreds[1], wantCreds[3]},
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 3,
			},
			anonRes: &pbs.ListCredentialsResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			}, // anonymous user does not have access to attributes
		},
		{
			name: "Filter to no credential",
			req:  &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res: &pbs.ListCredentialsResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
			anonRes: &pbs.ListCredentialsResponse{
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewService(ctx, iamRepoFn, staticRepoFn, 1000)
			require.NoError(t, err, "Couldn't create new host set service.")

			// Test non-anonymous listing
			got, gErr := s.ListCredentials(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err), "ListCredentialStore(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(t, gErr)
			assert.Empty(
				t,
				cmp.Diff(
					got,
					tc.res,
					protocmp.Transform(),
					protocmp.SortRepeated(func(x, y *pb.Credential) bool {
						return x.Id < y.Id
					}),
					cmpopts.SortSlices(func(a, b string) bool {
						return a < b
					}),
					protocmp.IgnoreFields(&pbs.ListCredentialsResponse{}, "list_token"),
				),
			)

			// Test anonymous listing
			got, gErr = s.ListCredentials(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), tc.req)
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

func TestGet(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(context.Background(), rw, rw, kkms)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)

	store := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	s, err := NewService(ctx, iamRepoFn, staticRepoFn, 1000)
	require.NoError(t, err)

	upCred := static.TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId())
	upCredPrev := static.TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId(), static.WithPublicId(fmt.Sprintf("%s_1234567890", globals.UsernamePasswordCredentialPreviousPrefix)))
	upHm, err := crypto.HmacSha256(context.Background(), []byte("pass"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
	require.NoError(t, err)

	updCred := static.TestUsernamePasswordDomainCredential(t, conn, wrapper, "user", "pass", "domain", store.GetPublicId(), prj.GetPublicId())
	updHm, err := crypto.HmacSha256(context.Background(), []byte("pass"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
	require.NoError(t, err)

	pCred := static.TestPasswordCredential(t, conn, wrapper, "pass", store.GetPublicId(), prj.GetPublicId())
	pHm, err := crypto.HmacSha256(context.Background(), []byte("pass"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
	require.NoError(t, err)

	spkCred := static.TestSshPrivateKeyCredential(t, conn, wrapper, "user", static.TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId())
	spkHm, err := crypto.HmacSha256(context.Background(), []byte(static.TestSshPrivateKeyPem), databaseWrapper, []byte(store.GetPublicId()), nil)
	require.NoError(t, err)

	spkCredWithPass := static.TestSshPrivateKeyCredential(t, conn, wrapper,
		"user", string(testdata.PEMEncryptedKeys[0].PEMBytes),
		store.GetPublicId(), prj.GetPublicId(),
		static.WithPrivateKeyPassphrase([]byte(testdata.PEMEncryptedKeys[0].EncryptionKey)))
	spkWithPassHm, err := crypto.HmacSha256(context.Background(), []byte(testdata.PEMEncryptedKeys[0].PEMBytes), databaseWrapper, []byte(store.GetPublicId()), nil)
	require.NoError(t, err)
	passHm, err := crypto.HmacSha256(context.Background(), []byte(testdata.PEMEncryptedKeys[0].EncryptionKey), databaseWrapper, []byte(store.GetPublicId()), nil)
	require.NoError(t, err)

	obj, objBytes := static.TestJsonObject(t)

	jsonCred := static.TestJsonCredential(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj)
	objectHmac, err := crypto.HmacSha256(context.Background(), objBytes, databaseWrapper, []byte(store.GetPublicId()), nil)
	require.NoError(t, err)

	cases := []struct {
		name string
		id   string
		res  *pbs.GetCredentialResponse
		err  error
	}{
		{
			name: "success-up",
			id:   upCred.GetPublicId(),
			res: &pbs.GetCredentialResponse{
				Item: &pb.Credential{
					Id:                upCred.GetPublicId(),
					CredentialStoreId: upCred.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              credential.UsernamePasswordSubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       upCred.CreateTime.GetTimestamp(),
					UpdatedTime:       upCred.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.Credential_UsernamePasswordAttributes{
						UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
							Username:     wrapperspb.String("user"),
							PasswordHmac: base64.RawURLEncoding.EncodeToString([]byte(upHm)),
						},
					},
				},
			},
		},
		{
			name: "success-up-prev-prefix",
			id:   upCredPrev.GetPublicId(),
			res: &pbs.GetCredentialResponse{
				Item: &pb.Credential{
					Id:                upCredPrev.GetPublicId(),
					CredentialStoreId: upCred.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              credential.UsernamePasswordSubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       upCredPrev.CreateTime.GetTimestamp(),
					UpdatedTime:       upCredPrev.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.Credential_UsernamePasswordAttributes{
						UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
							Username:     wrapperspb.String("user"),
							PasswordHmac: base64.RawURLEncoding.EncodeToString([]byte(upHm)),
						},
					},
				},
			},
		},
		{
			name: "success-upd",
			id:   updCred.GetPublicId(),
			res: &pbs.GetCredentialResponse{
				Item: &pb.Credential{
					Id:                updCred.GetPublicId(),
					CredentialStoreId: updCred.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              credential.UsernamePasswordDomainSubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       updCred.CreateTime.GetTimestamp(),
					UpdatedTime:       updCred.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
						UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
							Username:     wrapperspb.String("user"),
							PasswordHmac: base64.RawURLEncoding.EncodeToString([]byte(updHm)),
							Domain:       wrapperspb.String("domain"),
						},
					},
				},
			},
		},
		{
			name: "success-password-only-credential",
			id:   pCred.GetPublicId(),
			res: &pbs.GetCredentialResponse{
				Item: &pb.Credential{
					Id:                pCred.GetPublicId(),
					CredentialStoreId: pCred.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              credential.PasswordSubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       pCred.CreateTime.GetTimestamp(),
					UpdatedTime:       pCred.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.Credential_PasswordAttributes{
						PasswordAttributes: &pb.PasswordAttributes{
							PasswordHmac: base64.RawURLEncoding.EncodeToString([]byte(pHm)),
						},
					},
				},
			},
		},
		{
			name: "success-spk",
			id:   spkCred.GetPublicId(),
			res: &pbs.GetCredentialResponse{
				Item: &pb.Credential{
					Id:                spkCred.GetPublicId(),
					CredentialStoreId: spkCred.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              credential.SshPrivateKeySubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       spkCred.CreateTime.GetTimestamp(),
					UpdatedTime:       spkCred.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.Credential_SshPrivateKeyAttributes{
						SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
							Username:       wrapperspb.String("user"),
							PrivateKeyHmac: base64.RawURLEncoding.EncodeToString([]byte(spkHm)),
						},
					},
				},
			},
		},
		{
			name: "success-spk-with-pass",
			id:   spkCredWithPass.GetPublicId(),
			res: &pbs.GetCredentialResponse{
				Item: &pb.Credential{
					Id:                spkCredWithPass.GetPublicId(),
					CredentialStoreId: spkCredWithPass.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              credential.SshPrivateKeySubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       spkCredWithPass.CreateTime.GetTimestamp(),
					UpdatedTime:       spkCredWithPass.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.Credential_SshPrivateKeyAttributes{
						SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
							Username:                 wrapperspb.String("user"),
							PrivateKeyHmac:           base64.RawURLEncoding.EncodeToString([]byte(spkWithPassHm)),
							PrivateKeyPassphraseHmac: base64.RawURLEncoding.EncodeToString([]byte(passHm)),
						},
					},
				},
			},
		},
		{
			name: "success-json",
			id:   jsonCred.GetPublicId(),
			res: &pbs.GetCredentialResponse{
				Item: &pb.Credential{
					Id:                jsonCred.GetPublicId(),
					CredentialStoreId: jsonCred.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetProjectId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
					Type:              credential.JsonSubtype.String(),
					AuthorizedActions: testAuthorizedActions,
					CreatedTime:       jsonCred.CreateTime.GetTimestamp(),
					UpdatedTime:       jsonCred.UpdateTime.GetTimestamp(),
					Version:           1,
					Attrs: &pb.Credential_JsonAttributes{
						JsonAttributes: &pb.JsonAttributes{
							ObjectHmac: base64.RawURLEncoding.EncodeToString([]byte(objectHmac)),
						},
					},
				},
			},
		},
		{
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", globals.UsernamePasswordCredentialPrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", globals.StaticCredentialStorePrefix),
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &pbs.GetCredentialRequest{Id: tc.id}
			// Test non-anonymous get
			got, gErr := s.GetCredential(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), req)
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
			))

			// Test anonymous get
			got, gErr = s.GetCredential(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(globals.AnonymousUserId)), req)
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
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(context.Background(), rw, rw, kms)
	}

	_, prj := iam.TestScopes(t, iamRepo)

	store := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	s, err := NewService(ctx, iamRepoFn, staticRepoFn, 1000)
	require.NoError(t, err)

	upCred := static.TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId())
	updCred := static.TestUsernamePasswordDomainCredential(t, conn, wrapper, "user", "pass", "domain", store.GetPublicId(), prj.GetPublicId())
	pCred := static.TestPasswordCredential(t, conn, wrapper, "pass", store.GetPublicId(), prj.GetPublicId())
	spkCred := static.TestSshPrivateKeyCredential(t, conn, wrapper, "user", static.TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId())

	obj, _ := static.TestJsonObject(t)

	jsonCred := static.TestJsonCredential(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj)

	cases := []struct {
		name string
		id   string
		err  error
		res  *pbs.DeleteCredentialResponse
	}{
		{
			name: "success-up",
			id:   upCred.GetPublicId(),
		},
		{
			name: "success-upd",
			id:   updCred.GetPublicId(),
		},
		{
			name: "success-p",
			id:   pCred.GetPublicId(),
		},
		{
			name: "success-spk",
			id:   spkCred.GetPublicId(),
		},
		{
			name: "success-json",
			id:   jsonCred.GetPublicId(),
		},
		{
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", globals.UsernamePasswordCredentialPrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", globals.StaticCredentialStorePrefix),
			err:  handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gErr := s.DeleteCredential(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), &pbs.DeleteCredentialRequest{Id: tc.id})
			assert.EqualValuesf(t, tc.res, got, "DeleteCredentialStore got response %q, wanted %q", got, tc.res)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err))
				return
			}
			require.NoError(t, gErr)
			g, err := s.GetCredential(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), &pbs.GetCredentialRequest{Id: tc.id})
			assert.Nil(t, g)
			assert.True(t, errors.Is(err, handlers.NotFoundError()))
		})
	}
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	repoFn := func() (*static.Repository, error) {
		return static.NewRepository(context.Background(), rw, rw, kkms)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	store := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	obj, objBytes := static.TestJsonObject(t)

	cases := []struct {
		name     string
		req      *pbs.CreateCredentialRequest
		res      *pbs.CreateCredentialResponse
		idPrefix string
		err      error
		wantErr  bool
	}{
		{
			name: "Can't specify Id",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Id:                globals.UsernamePasswordCredentialPrefix + "_notallowed",
				Type:              credential.UsernamePasswordSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordAttributes{
					UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid Credential Store Id",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: "p_invalidid",
				Type:              credential.UsernamePasswordSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordAttributes{
					UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				CreatedTime:       timestamppb.Now(),
				Type:              credential.UsernamePasswordSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordAttributes{
					UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Updated Time",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				UpdatedTime:       timestamppb.Now(),
				Type:              credential.UsernamePasswordSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordAttributes{
					UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide type",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Attrs: &pb.Credential_UsernamePasswordAttributes{
					UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide username",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.UsernamePasswordSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordAttributes{
					UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide password",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.UsernamePasswordSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordAttributes{
					UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
						Username: wrapperspb.String("username"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id UPD",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Id:                globals.UsernamePasswordDomainCredentialPrefix + "_notallowed",
				Type:              credential.UsernamePasswordDomainSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
					UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
						Domain:   wrapperspb.String("domain"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid Credential Store Id UPD",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: "p_invalidid",
				Type:              credential.UsernamePasswordDomainSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
					UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
						Domain:   wrapperspb.String("domain"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				CreatedTime:       timestamppb.Now(),
				Type:              credential.UsernamePasswordDomainSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
					UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
						Domain:   wrapperspb.String("domain"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Updated Time",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				UpdatedTime:       timestamppb.Now(),
				Type:              credential.UsernamePasswordDomainSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
					UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
						Domain:   wrapperspb.String("domain"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide type",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
					UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
						Domain:   wrapperspb.String("domain"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide username",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.UsernamePasswordDomainSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
					UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
						Password: wrapperspb.String("password"),
						Domain:   wrapperspb.String("domain"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide password",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.UsernamePasswordDomainSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
					UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
						Username: wrapperspb.String("username"),
						Domain:   wrapperspb.String("domain"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},

		{
			name: "Must provide domain",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.UsernamePasswordDomainSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
					UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Id P",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Id:                globals.PasswordCredentialPrefix + "_notallowed",
				Type:              credential.PasswordSubtype.String(),
				Attrs: &pb.Credential_PasswordAttributes{
					PasswordAttributes: &pb.PasswordAttributes{
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Invalid Credential Store Id P",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: "p_invalidid",
				Type:              credential.PasswordSubtype.String(),
				Attrs: &pb.Credential_PasswordAttributes{
					PasswordAttributes: &pb.PasswordAttributes{
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				CreatedTime:       timestamppb.Now(),
				Type:              credential.PasswordSubtype.String(),
				Attrs: &pb.Credential_PasswordAttributes{
					PasswordAttributes: &pb.PasswordAttributes{
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Can't specify Updated Time",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				UpdatedTime:       timestamppb.Now(),
				Type:              credential.PasswordSubtype.String(),
				Attrs: &pb.Credential_PasswordAttributes{
					PasswordAttributes: &pb.PasswordAttributes{
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide type",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Attrs: &pb.Credential_PasswordAttributes{
					PasswordAttributes: &pb.PasswordAttributes{
						Password: wrapperspb.String("password"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide password",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.PasswordSubtype.String(),
				Attrs: &pb.Credential_PasswordAttributes{
					PasswordAttributes: &pb.PasswordAttributes{
						// Empty password
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide private key",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.SshPrivateKeySubtype.String(),
				Attrs: &pb.Credential_SshPrivateKeyAttributes{
					SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
						Username: wrapperspb.String("username"),
					},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Must provide json secret",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.JsonSubtype.String(),
				Attrs: &pb.Credential_JsonAttributes{
					JsonAttributes: &pb.JsonAttributes{},
				},
			}},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "valid-up",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.UsernamePasswordSubtype.String(),
				Attrs: &pb.Credential_UsernamePasswordAttributes{
					UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
						Username: wrapperspb.String("username"),
						Password: wrapperspb.String("password"),
					},
				},
			}},
			idPrefix: globals.UsernamePasswordCredentialPrefix + "_",
			res: &pbs.CreateCredentialResponse{
				Uri: fmt.Sprintf("credentials/%s_", globals.UsernamePasswordCredentialPrefix),
				Item: &pb.Credential{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              credential.UsernamePasswordSubtype.String(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "valid-p",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.PasswordSubtype.String(),
				Attrs: &pb.Credential_PasswordAttributes{
					PasswordAttributes: &pb.PasswordAttributes{
						Password: wrapperspb.String("password"),
					},
				},
			}},
			idPrefix: globals.PasswordCredentialPrefix + "_",
			res: &pbs.CreateCredentialResponse{
				Uri: fmt.Sprintf("credentials/%s_", globals.PasswordCredentialPrefix),
				Item: &pb.Credential{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              credential.PasswordSubtype.String(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "valid-spk",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.SshPrivateKeySubtype.String(),
				Attrs: &pb.Credential_SshPrivateKeyAttributes{
					SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
						Username:   wrapperspb.String("username"),
						PrivateKey: wrapperspb.String(static.TestSshPrivateKeyPem),
					},
				},
			}},
			idPrefix: globals.SshPrivateKeyCredentialPrefix + "_",
			res: &pbs.CreateCredentialResponse{
				Uri: fmt.Sprintf("credentials/%s_", globals.SshPrivateKeyCredentialPrefix),
				Item: &pb.Credential{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              credential.SshPrivateKeySubtype.String(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "valid-spk-with-passphrase",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.SshPrivateKeySubtype.String(),
				Attrs: &pb.Credential_SshPrivateKeyAttributes{
					SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
						Username:             wrapperspb.String("username"),
						PrivateKey:           wrapperspb.String(string(testdata.PEMEncryptedKeys[0].PEMBytes)),
						PrivateKeyPassphrase: wrapperspb.String(testdata.PEMEncryptedKeys[0].EncryptionKey),
					},
				},
			}},
			idPrefix: globals.SshPrivateKeyCredentialPrefix + "_",
			res: &pbs.CreateCredentialResponse{
				Uri: fmt.Sprintf("credentials/%s_", globals.SshPrivateKeyCredentialPrefix),
				Item: &pb.Credential{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              credential.SshPrivateKeySubtype.String(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
		{
			name: "valid-json",
			req: &pbs.CreateCredentialRequest{Item: &pb.Credential{
				CredentialStoreId: store.GetPublicId(),
				Type:              credential.JsonSubtype.String(),
				Attrs: &pb.Credential_JsonAttributes{
					JsonAttributes: &pb.JsonAttributes{
						Object: obj.Struct,
					},
				},
			}},
			idPrefix: globals.JsonCredentialPrefix + "_",
			res: &pbs.CreateCredentialResponse{
				Uri: fmt.Sprintf("credentials/%s_", globals.JsonCredentialPrefix),
				Item: &pb.Credential{
					Id:                store.GetPublicId(),
					CredentialStoreId: store.GetPublicId(),
					CreatedTime:       store.GetCreateTime().GetTimestamp(),
					UpdatedTime:       store.GetUpdateTime().GetTimestamp(),
					Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: prj.GetType(), ParentScopeId: prj.GetParentId()},
					Version:           1,
					Type:              credential.JsonSubtype.String(),
					AuthorizedActions: testAuthorizedActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := NewService(ctx, iamRepoFn, repoFn, 1000)
			require.NoError(err, "Error when getting new credential store service.")

			got, gErr := s.CreateCredential(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), tc.req)
			if tc.wantErr || tc.err != nil {
				require.Error(gErr)
				if tc.err != nil {
					assert.True(errors.Is(gErr, tc.err), "CreateCredential(...) got error %v, wanted %v", gErr, tc.err)
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
				assert.True(gotCreateTime.AsTime().After(store.CreateTime.AsTime()), "New credential should have been created after default credential store. Was created %v, which is after %v", gotCreateTime, store.CreateTime.AsTime())
				assert.True(gotUpdateTime.AsTime().After(store.CreateTime.AsTime()), "New credential should have been updated after default credential store. Was updated %v, which is after %v", gotUpdateTime, store.CreateTime.AsTime())

				// Calculate hmac
				databaseWrapper, err := kkms.GetWrapper(ctx, prj.PublicId, kms.KeyPurposeDatabase)
				require.NoError(err)

				switch tc.req.Item.Type {
				case credential.UsernamePasswordSubtype.String():
					password := tc.req.GetItem().GetUsernamePasswordAttributes().GetPassword().GetValue()
					hm, err := crypto.HmacSha256(ctx, []byte(password), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
					require.NoError(err)

					// Validate attributes equal
					assert.Equal(tc.req.GetItem().GetUsernamePasswordAttributes().GetUsername().GetValue(),
						got.GetItem().GetUsernamePasswordAttributes().GetUsername().GetValue())
					assert.Equal(base64.RawURLEncoding.EncodeToString([]byte(hm)), got.GetItem().GetUsernamePasswordAttributes().GetPasswordHmac())
					assert.Empty(got.GetItem().GetUsernamePasswordAttributes().GetPassword())

				case credential.PasswordSubtype.String():
					password := tc.req.GetItem().GetPasswordAttributes().GetPassword().GetValue()
					hm, err := crypto.HmacSha256(ctx, []byte(password), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
					require.NoError(err)

					// Validate attributes equal
					assert.Equal(base64.RawURLEncoding.EncodeToString([]byte(hm)), got.GetItem().GetPasswordAttributes().GetPasswordHmac())
					assert.Empty(got.GetItem().GetPasswordAttributes().GetPassword())

				case credential.SshPrivateKeySubtype.String():
					pk := tc.req.GetItem().GetSshPrivateKeyAttributes().GetPrivateKey().GetValue()
					hm, err := crypto.HmacSha256(ctx, []byte(pk), databaseWrapper, []byte(store.GetPublicId()), nil)
					require.NoError(err)

					// Validate attributes equal
					assert.Equal(tc.req.GetItem().GetSshPrivateKeyAttributes().GetUsername().GetValue(),
						got.GetItem().GetSshPrivateKeyAttributes().GetUsername().GetValue())
					assert.Equal(base64.RawURLEncoding.EncodeToString([]byte(hm)), got.GetItem().GetSshPrivateKeyAttributes().GetPrivateKeyHmac())
					assert.Empty(got.GetItem().GetSshPrivateKeyAttributes().GetPrivateKey())

					if pass := tc.req.GetItem().GetSshPrivateKeyAttributes().GetPrivateKeyPassphrase().GetValue(); pass != "" {
						hm, err := crypto.HmacSha256(ctx, []byte(pass), databaseWrapper, []byte(store.GetPublicId()), nil)
						require.NoError(err)

						assert.Equal(base64.RawURLEncoding.EncodeToString([]byte(hm)), got.GetItem().GetSshPrivateKeyAttributes().GetPrivateKeyPassphraseHmac())
						assert.Empty(got.GetItem().GetSshPrivateKeyAttributes().GetPrivateKeyPassphrase())
					}

				case credential.JsonSubtype.String():
					hm, err := crypto.HmacSha256(ctx, objBytes, databaseWrapper, []byte(store.GetPublicId()), nil)
					require.NoError(err)

					// Validate attributes equal
					assert.Equal(base64.RawURLEncoding.EncodeToString([]byte(hm)), got.GetItem().GetJsonAttributes().GetObjectHmac())
					assert.Empty(got.GetItem().GetJsonAttributes().GetObject())

				default:
					require.Fail("unknown type")
				}

				// Clear attributes for compare below
				got.Item.Attrs = nil

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(
				got,
				tc.res,
				protocmp.Transform(),
				protocmp.SortRepeatedFields(got),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
			), "CreateCredential(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

const TestSecondarySshPrivateKeyPem = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDxfwhEAZKrnsbQxOjVA3PFiB3bW3tSpNKx8TdMiCqlzQAAAJDmpbfr5qW3
6wAAAAtzc2gtZWQyNTUxOQAAACDxfwhEAZKrnsbQxOjVA3PFiB3bW3tSpNKx8TdMiCqlzQ
AAAEBvvkQkH06ad2GpX1VVARzu9NkHA6gzamAaQ/hkn5FuZvF/CEQBkquextDE6NUDc8WI
Hdtbe1Kk0rHxN0yIKqXNAAAACWplZmZAYXJjaAECAwQ=
-----END OPENSSH PRIVATE KEY-----
`

func TestUpdate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kkms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(context.Background(), rw, rw, kkms)
	}

	_, prj := iam.TestScopes(t, iamRepo)
	ctx := auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId())
	s, err := NewService(ctx, iamRepoFn, staticRepoFn, 1000)
	require.NoError(t, err)

	fieldmask := func(paths ...string) *fieldmaskpb.FieldMask {
		return &fieldmaskpb.FieldMask{Paths: paths}
	}

	store := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	freshCredUp := func(user, pass string) (*static.UsernamePasswordCredential, func()) {
		t.Helper()
		cred := static.TestUsernamePasswordCredential(t, conn, wrapper, user, pass, store.GetPublicId(), prj.GetPublicId())
		clean := func() {
			_, err := s.DeleteCredential(ctx, &pbs.DeleteCredentialRequest{Id: cred.GetPublicId()})
			require.NoError(t, err)
		}
		return cred, clean
	}

	freshCredUpd := func(user, pass, domain string) (*static.UsernamePasswordDomainCredential, func()) {
		t.Helper()
		cred := static.TestUsernamePasswordDomainCredential(t, conn, wrapper, user, pass, domain, store.GetPublicId(), prj.GetPublicId())
		clean := func() {
			_, err := s.DeleteCredential(ctx, &pbs.DeleteCredentialRequest{Id: cred.GetPublicId()})
			require.NoError(t, err)
		}
		return cred, clean
	}

	freshCredP := func(pass string) (*static.PasswordCredential, func()) {
		t.Helper()
		cred := static.TestPasswordCredential(t, conn, wrapper, pass, store.GetPublicId(), prj.GetPublicId())
		clean := func() {
			_, err := s.DeleteCredential(ctx, &pbs.DeleteCredentialRequest{Id: cred.GetPublicId()})
			require.NoError(t, err)
		}
		return cred, clean
	}

	freshCredSpk := func(user string) (*static.SshPrivateKeyCredential, func()) {
		t.Helper()
		cred := static.TestSshPrivateKeyCredential(t, conn, wrapper, user, static.TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId())
		clean := func() {
			_, err := s.DeleteCredential(ctx, &pbs.DeleteCredentialRequest{Id: cred.GetPublicId()})
			require.NoError(t, err)
		}
		return cred, clean
	}

	freshCredJson := func() (*static.JsonCredential, func()) {
		t.Helper()
		obj, _ := static.TestJsonObject(t)
		cred := static.TestJsonCredential(t, conn, wrapper, store.GetPublicId(), prj.GetPublicId(), obj)
		clean := func() {
			_, err := s.DeleteCredential(ctx, &pbs.DeleteCredentialRequest{Id: cred.GetPublicId()})
			require.NoError(t, err)
		}
		return cred, clean
	}

	secondSecret := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"username": structpb.NewStringValue("new-user"),
			"password": structpb.NewStringValue("new-password"),
			"hash":     structpb.NewStringValue("0123456789"),
		},
	}
	secondSecretBytes, err := json.Marshal(secondSecret)
	require.NoError(t, err)

	databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)

	successFailCases := []struct {
		name             string
		req              *pbs.UpdateCredentialRequest
		res              func(cred *pb.Credential) *pb.Credential
		expErrorContains string
	}{
		{
			name: "name",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("name"),
				Item: &pb.Credential{
					Name: wrapperspb.String("new-name"),
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				out.Name = wrapperspb.String("new-name")
				return out
			},
		},
		{
			name: "description",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("description"),
				Item: &pb.Credential{
					Description: wrapperspb.String("new-description"),
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				out.Description = wrapperspb.String("new-description")
				return out
			},
		},
		{
			name: "name-and-description",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("name", "description"),
				Item: &pb.Credential{
					Name:        wrapperspb.String("new-name"),
					Description: wrapperspb.String("new-description"),
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				out.Name = wrapperspb.String("new-name")
				out.Description = wrapperspb.String("new-description")
				return out
			},
		},
		{
			name: "name-and-description-spk",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("name", "description"),
				Item: &pb.Credential{
					Name:        wrapperspb.String("new-name"),
					Description: wrapperspb.String("new-description"),
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				out.Name = wrapperspb.String("new-name")
				out.Description = wrapperspb.String("new-description")
				return out
			},
		},
		{
			name: "update-username-up",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.username"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_UsernamePasswordAttributes{
						UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
							Username: wrapperspb.String("new-user-name"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				out.GetUsernamePasswordAttributes().Username = wrapperspb.String("new-user-name")
				return out
			},
		},
		{
			name: "update-username-domainupd",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.username"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
						UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
							Username: wrapperspb.String("new-user-name"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				out.GetUsernamePasswordDomainAttributes().Username = wrapperspb.String("new-user-name")
				return out
			},
		},
		{
			name: "update-username-spk",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.username"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_SshPrivateKeyAttributes{
						SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
							Username: wrapperspb.String("new-user-name"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				out.GetSshPrivateKeyAttributes().Username = wrapperspb.String("new-user-name")
				return out
			},
		},
		{
			name: "update-password",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.password"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_UsernamePasswordAttributes{
						UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
							Password: wrapperspb.String("new-password"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				hm, err := crypto.HmacSha256(context.Background(), []byte("new-password"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
				require.NoError(t, err)
				out.GetUsernamePasswordAttributes().PasswordHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-password-domainupd",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.password"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
						UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
							Password: wrapperspb.String("new-password"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				hm, err := crypto.HmacSha256(context.Background(), []byte("new-password"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
				require.NoError(t, err)
				out.GetUsernamePasswordDomainAttributes().PasswordHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-domain-domainupd",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.domain"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
						UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
							Domain: wrapperspb.String("new-domain"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				out.GetUsernamePasswordDomainAttributes().Domain = wrapperspb.String("new-domain")
				return out
			},
		},
		{
			name: "update-password-attributes-passwordOnly",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.password"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_PasswordAttributes{
						PasswordAttributes: &pb.PasswordAttributes{
							Password: wrapperspb.String("new-password"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				hm, err := crypto.HmacSha256(context.Background(), []byte("new-password"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
				require.NoError(t, err)
				out.GetPasswordAttributes().PasswordHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-spk",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.private_key"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_SshPrivateKeyAttributes{
						SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
							PrivateKey: wrapperspb.String(TestSecondarySshPrivateKeyPem),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)
				hm, err := crypto.HmacSha256(context.Background(), []byte(TestSecondarySshPrivateKeyPem), databaseWrapper, []byte(store.GetPublicId()), nil)
				require.NoError(t, err)
				out.GetSshPrivateKeyAttributes().PrivateKeyHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-username-and-password",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.username", "attributes.password"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_UsernamePasswordAttributes{
						UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
							Username: wrapperspb.String("new-username"),
							Password: wrapperspb.String("new-password"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)

				out.GetUsernamePasswordAttributes().Username = wrapperspb.String("new-username")

				hm, err := crypto.HmacSha256(context.Background(), []byte("new-password"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
				require.NoError(t, err)
				out.GetUsernamePasswordAttributes().PasswordHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-username-password-domainupd",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.username", "attributes.password"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
						UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
							Username: wrapperspb.String("new-username"),
							Password: wrapperspb.String("new-password"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)

				out.GetUsernamePasswordDomainAttributes().Username = wrapperspb.String("new-username")

				hm, err := crypto.HmacSha256(context.Background(), []byte("new-password"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
				require.NoError(t, err)
				out.GetUsernamePasswordDomainAttributes().PasswordHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-username-password-and-domain-domainupd",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.username", "attributes.password", "attributes.domain"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_UsernamePasswordDomainAttributes{
						UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
							Username: wrapperspb.String("new-username"),
							Password: wrapperspb.String("new-password"),
							Domain:   wrapperspb.String("new-domain"),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)

				out.GetUsernamePasswordDomainAttributes().Username = wrapperspb.String("new-username")

				hm, err := crypto.HmacSha256(context.Background(), []byte("new-password"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
				require.NoError(t, err)
				out.GetUsernamePasswordDomainAttributes().Domain = wrapperspb.String("new-domain")
				out.GetUsernamePasswordDomainAttributes().PasswordHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-username-and-spk",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.username", "attributes.private_key"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_SshPrivateKeyAttributes{
						SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
							Username:   wrapperspb.String("new-username"),
							PrivateKey: wrapperspb.String(TestSecondarySshPrivateKeyPem),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)

				out.GetSshPrivateKeyAttributes().Username = wrapperspb.String("new-username")

				hm, err := crypto.HmacSha256(context.Background(), []byte(TestSecondarySshPrivateKeyPem), databaseWrapper, []byte(store.GetPublicId()), nil)
				require.NoError(t, err)
				out.GetSshPrivateKeyAttributes().PrivateKeyHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-spk-with-passphrase",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.private_key", "attributes.private_key_passphrase"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_SshPrivateKeyAttributes{
						SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
							PrivateKey:           wrapperspb.String(string(testdata.PEMEncryptedKeys[0].PEMBytes)),
							PrivateKeyPassphrase: wrapperspb.String(testdata.PEMEncryptedKeys[0].EncryptionKey),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)

				hm, err := crypto.HmacSha256(context.Background(), testdata.PEMEncryptedKeys[0].PEMBytes, databaseWrapper, []byte(store.GetPublicId()), nil)
				require.NoError(t, err)
				out.GetSshPrivateKeyAttributes().PrivateKeyHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))

				hm, err = crypto.HmacSha256(context.Background(), []byte(testdata.PEMEncryptedKeys[0].EncryptionKey), databaseWrapper, []byte(store.GetPublicId()), nil)
				require.NoError(t, err)
				out.GetSshPrivateKeyAttributes().PrivateKeyPassphraseHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-json",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.object.username", "attributes.object.password", "attributes.object.hash"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_JsonAttributes{
						JsonAttributes: &pb.JsonAttributes{
							Object: secondSecret,
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)

				hm, err := crypto.HmacSha256(context.Background(), secondSecretBytes, databaseWrapper, []byte(store.GetPublicId()), nil)
				require.NoError(t, err)
				out.GetJsonAttributes().ObjectHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				return out
			},
		},
		{
			name: "update-empty-object-json",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.object.password"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_JsonAttributes{
						JsonAttributes: &pb.JsonAttributes{
							Object: &structpb.Struct{},
						},
					},
				},
			},
			expErrorContains: "This is a required field and cannot be set to empty",
		},
		{
			name: "update-nil-object-json",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.object.password"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_JsonAttributes{
						JsonAttributes: &pb.JsonAttributes{},
					},
				},
			},
			expErrorContains: "This is a required field and cannot be set to empty",
		},
		{
			name: "update-spk-with-bad-passphrase",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.private_key", "attributes.private_key_passphrase"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_SshPrivateKeyAttributes{
						SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
							PrivateKey:           wrapperspb.String(string(testdata.PEMEncryptedKeys[0].PEMBytes)),
							PrivateKeyPassphrase: wrapperspb.String(strings.ToLower(testdata.PEMEncryptedKeys[0].EncryptionKey)),
						},
					},
				},
			},
			expErrorContains: "Incorrect private key passphrase",
		},
		{
			name: "update-non-passphrase-spk-with-passphrase",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.private_key"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_SshPrivateKeyAttributes{
						SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
							PrivateKey:           wrapperspb.String(static.TestSshPrivateKeyPem),
							PrivateKeyPassphrase: wrapperspb.String(testdata.PEMEncryptedKeys[0].EncryptionKey),
						},
					},
				},
			},
			expErrorContains: "Passphrase supplied for unencrypted key",
		},
		{
			name: "update-non-passphrase-spk-with-no-passphrase",
			req: &pbs.UpdateCredentialRequest{
				UpdateMask: fieldmask("attributes.private_key"),
				Item: &pb.Credential{
					Attrs: &pb.Credential_SshPrivateKeyAttributes{
						SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
							PrivateKey: wrapperspb.String(static.TestSshPrivateKeyPem),
						},
					},
				},
			},
			res: func(in *pb.Credential) *pb.Credential {
				out := proto.Clone(in).(*pb.Credential)

				hm, err := crypto.HmacSha256(context.Background(), []byte(static.TestSshPrivateKeyPem), databaseWrapper, []byte(store.GetPublicId()), nil)
				require.NoError(t, err)
				out.GetSshPrivateKeyAttributes().PrivateKeyHmac = base64.RawURLEncoding.EncodeToString([]byte(hm))
				out.GetSshPrivateKeyAttributes().PrivateKeyPassphraseHmac = ""

				return out
			},
		},
	}

	for _, tc := range successFailCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var cred credential.Static
			var cleanup func()

			if strings.Contains(tc.name, "spk") {
				cred, cleanup = freshCredSpk("user")
			} else if strings.Contains(tc.name, "json") {
				cred, cleanup = freshCredJson()
			} else if strings.Contains(tc.name, "domainupd") {
				cred, cleanup = freshCredUpd("user", "pass", "domain")
			} else if strings.Contains(tc.name, "passwordOnly") {
				cred, cleanup = freshCredP("pass")
			} else {
				cred, cleanup = freshCredUp("user", "pass")
			}
			defer cleanup()

			if tc.req.Item.GetVersion() == 0 {
				tc.req.Item.Version = 1
			}
			if tc.req.GetId() == "" {
				tc.req.Id = cred.GetPublicId()
			}
			resToChange, err := s.GetCredential(ctx, &pbs.GetCredentialRequest{Id: cred.GetPublicId()})
			require.NoError(err)

			got, gErr := s.UpdateCredential(ctx, tc.req)
			if tc.expErrorContains != "" {
				require.NotNil(gErr)
				assert.Contains(gErr.Error(), tc.expErrorContains)
				return
			}
			require.NoError(gErr)
			require.NotNil(got)

			want := &pbs.UpdateCredentialResponse{Item: tc.res(resToChange.GetItem())}

			gotUpdateTime := got.GetItem().GetUpdatedTime()
			created := cred.GetCreateTime().GetTimestamp()
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
			))
		})
	}

	// cant update read only fields
	credJson, cleanupJson := freshCredJson()
	defer cleanupJson()

	// cant update read only fields
	credUp, cleanUp := freshCredUp("user", "pass")
	defer cleanUp()

	// cant update read only fields
	credUpd, cleanUpd := freshCredUpd("user", "pass", "domain")
	defer cleanUpd()

	// cant update read only fields
	credP, cleanP := freshCredP("pass")
	defer cleanP()

	newStore := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	roCases := []struct {
		path    string
		item    *pb.Credential
		matcher func(t *testing.T, e error) // When not set defaults to checking against InvalidArgument Error
	}{
		{
			path: "type",
			item: &pb.Credential{Type: "something"},
		},
		{
			path: "store_id",
			item: &pb.Credential{CredentialStoreId: newStore.GetPublicId()},
		},
		{
			path: "updated_time",
			item: &pb.Credential{UpdatedTime: timestamppb.Now()},
		},
		{
			path: "created_time",
			item: &pb.Credential{UpdatedTime: timestamppb.Now()},
		},
		{
			path: "authorized_actions",
			item: &pb.Credential{AuthorizedActions: append(testAuthorizedActions, "another")},
		},
	}
	for _, tc := range roCases {
		t.Run(fmt.Sprintf("ReadOnlyField/%s", tc.path), func(t *testing.T) {
			req := &pbs.UpdateCredentialRequest{
				Id:         credUp.GetPublicId(),
				Item:       tc.item,
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{tc.path}},
			}
			req.Item.Version = credUp.Version

			got, gErr := s.UpdateCredential(ctx, req)
			assert.Error(t, gErr)
			matcher := tc.matcher
			if matcher == nil {
				matcher = func(t *testing.T, e error) {
					assert.Truef(t, errors.Is(gErr, handlers.ApiErrorWithCode(codes.InvalidArgument)), "got error %v, wanted invalid argument", gErr)
				}
			}
			matcher(t, gErr)
			assert.Nil(t, got)

			req = &pbs.UpdateCredentialRequest{
				Id:         credJson.GetPublicId(),
				Item:       tc.item,
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{tc.path}},
			}
			req.Item.Version = credJson.Version

			got, gErr = s.UpdateCredential(ctx, req)
			assert.Error(t, gErr)
			matcher = tc.matcher
			if matcher == nil {
				matcher = func(t *testing.T, e error) {
					assert.Truef(t, errors.Is(gErr, handlers.ApiErrorWithCode(codes.InvalidArgument)), "got error %v, wanted invalid argument", gErr)
				}
			}
			matcher(t, gErr)
			assert.Nil(t, got)

			req = &pbs.UpdateCredentialRequest{
				Id:         credUpd.GetPublicId(),
				Item:       tc.item,
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{tc.path}},
			}
			req.Item.Version = credUpd.Version

			got, gErr = s.UpdateCredential(ctx, req)
			assert.Error(t, gErr)
			matcher = tc.matcher
			if matcher == nil {
				matcher = func(t *testing.T, e error) {
					assert.Truef(t, errors.Is(gErr, handlers.ApiErrorWithCode(codes.InvalidArgument)), "got error %v, wanted invalid argument", gErr)
				}
			}
			matcher(t, gErr)
			assert.Nil(t, got)

			req = &pbs.UpdateCredentialRequest{
				Id:         credP.GetPublicId(),
				Item:       tc.item,
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{tc.path}},
			}
			req.Item.Version = credP.Version

			got, gErr = s.UpdateCredential(ctx, req)
			assert.Error(t, gErr)
			matcher = tc.matcher
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
	kmsRepo := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	iamRepo := iam.TestRepo(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	staticRepoFn := func() (*static.Repository, error) {
		return static.NewRepository(ctx, rw, rw, kmsRepo)
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsRepo)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kmsRepo)
	}
	repo, err := staticRepoFn()
	require.NoError(err)
	tokenRepo, err := tokenRepoFn()
	require.NoError(err)

	_, prjNoStores := iam.TestScopes(t, iamRepo)
	o, prj := iam.TestScopes(t, iamRepo)
	credStore := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	emptyStore := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	databaseWrapper, err := kmsRepo.GetWrapper(ctx, prj.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(err)

	var allCredentials []*pb.Credential
	testObj, testObjBytes := static.TestJsonObject(t)
	for _, l := range static.TestJsonCredentials(t, conn, wrapper, credStore.GetPublicId(), prj.PublicId, testObj, 5) {
		hm, err := crypto.HmacSha256(ctx, []byte(testObjBytes), databaseWrapper, []byte(credStore.GetPublicId()), nil)
		require.NoError(err)
		allCredentials = append(allCredentials, staticJsonCredentialToProto(l, prj, hm))
	}
	for _, l := range static.TestSshPrivateKeyCredentials(t, conn, wrapper, "username", static.TestSshPrivateKeyPem, credStore.GetPublicId(), prj.PublicId, 5) {
		hm, err := crypto.HmacSha256(ctx, []byte(static.TestSshPrivateKeyPem), databaseWrapper, []byte(credStore.GetPublicId()), nil)
		require.NoError(err)
		allCredentials = append(allCredentials, staticSshCredentialToProto(l, prj, hm))
	}
	for _, l := range static.TestUsernamePasswordDomainCredentials(t, conn, wrapper, "username", "password", "domain", credStore.GetPublicId(), prj.PublicId, 5) {
		hm, err := crypto.HmacSha256(ctx, []byte("password"), databaseWrapper, []byte(credStore.GetPublicId()), nil, crypto.WithEd25519())
		require.NoError(err)
		allCredentials = append(allCredentials, staticUsernamePasswordDomainCredentialToProto(l, prj, hm))
	}
	for _, l := range static.TestUsernamePasswordCredentials(t, conn, wrapper, "username", "password", credStore.GetPublicId(), prj.PublicId, 5) {
		hm, err := crypto.HmacSha256(ctx, []byte("password"), databaseWrapper, []byte(credStore.GetPublicId()), nil, crypto.WithEd25519())
		require.NoError(err)
		allCredentials = append(allCredentials, staticUsernamePasswordCredentialToProto(l, prj, hm))
	}

	// Reverse slices since response is ordered by created_time descending (newest first)
	slices.Reverse(allCredentials)

	// Run analyze to update postgres meta tables
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(err)

	authMethod := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	// auth account is only used to join auth method to user.
	// We don't do anything else with the auth account in the test setup.
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
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsRepo, &requestInfo)

	s, err := NewService(ctx, iamRepoFn, staticRepoFn, 1000)
	require.NoError(err)

	// Start paginating, recursively
	req := &pbs.ListCredentialsRequest{
		CredentialStoreId: credStore.PublicId,
		Filter:            "",
		ListToken:         "",
		PageSize:          2,
	}
	got, err := s.ListCredentials(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 2)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialsResponse{
				Items:        allCredentials[0:2],
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 20,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialsResponse{}, "list_token"),
		),
	)

	// Request second page
	req.ListToken = got.ListToken
	got, err = s.ListCredentials(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 2)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialsResponse{
				Items:        allCredentials[2:4],
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 20,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialsResponse{}, "list_token"),
		),
	)

	// Request rest of results
	req.ListToken = got.ListToken
	req.PageSize = 16
	got, err = s.ListCredentials(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 16)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialsResponse{
				Items:        allCredentials[4:],
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 20,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialsResponse{}, "list_token"),
		),
	)

	// Create another credential
	newCred := static.TestJsonCredential(t, conn, wrapper, credStore.GetPublicId(), prj.GetPublicId(), testObj)
	hm, err := crypto.HmacSha256(ctx, []byte(testObjBytes), databaseWrapper, []byte(credStore.GetPublicId()), nil)
	require.NoError(err)
	pbNewCred := staticJsonCredentialToProto(newCred, prj, hm)
	// Add to the front since it's most recently updated
	allCredentials = append([]*pb.Credential{pbNewCred}, allCredentials...)

	// Delete one of the other credentials
	_, err = repo.DeleteCredential(ctx, prj.GetPublicId(), allCredentials[len(allCredentials)-1].GetId())
	require.NoError(err)
	deletedCred := allCredentials[len(allCredentials)-1]
	allCredentials = allCredentials[:len(allCredentials)-1]

	// Update one of the other credentials
	allCredentials[1].Name = wrapperspb.String("new-name")
	allCredentials[1].Version = 2
	updatedCredential := &static.UsernamePasswordCredential{
		UsernamePasswordCredential: &store.UsernamePasswordCredential{
			PublicId: allCredentials[1].GetId(),
			Name:     allCredentials[1].GetName().GetValue(),
			StoreId:  allCredentials[1].GetCredentialStoreId(),
		},
	}
	cred, _, err := repo.UpdateUsernamePasswordCredential(ctx, prj.GetPublicId(), updatedCredential, 1, []string{"name"})
	require.NoError(err)
	allCredentials[1].UpdatedTime = cred.UpdateTime.GetTimestamp()
	allCredentials[1].Version = cred.GetVersion()
	// Add to the front since it's most recently updated
	allCredentials = append(
		[]*pb.Credential{allCredentials[1]},
		append(
			[]*pb.Credential{allCredentials[0]},
			allCredentials[2:]...,
		)...,
	)

	// Run analyze to update postgres meta tables
	_, err = sqlDB.ExecContext(ctx, "analyze")
	require.NoError(err)

	// Request updated results
	req.ListToken = got.ListToken
	req.PageSize = 1
	got, err = s.ListCredentials(ctx, req)
	require.NoError(err)
	assert.Len(got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialsResponse{
				Items:        []*pb.Credential{allCredentials[0]},
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "updated_time",
				SortDir:      "desc",
				// Should contain the deleted credential
				RemovedIds:   []string{deletedCred.Id},
				EstItemCount: 20,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialsResponse{}, "list_token"),
		),
	)
	// Get next page
	req.ListToken = got.ListToken
	got, err = s.ListCredentials(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialsResponse{
				Items:        []*pb.Credential{allCredentials[1]},
				ResponseType: "complete",
				SortBy:       "updated_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 20,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialsResponse{}, "list_token"),
		),
	)

	// Request new page with filter requiring looping
	// to fill the page.
	req.ListToken = ""
	req.PageSize = 1
	req.Filter = fmt.Sprintf(`"/item/id"==%q or "/item/id"==%q`, allCredentials[len(allCredentials)-2].Id, allCredentials[len(allCredentials)-1].Id)
	got, err = s.ListCredentials(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialsResponse{
				Items:        []*pb.Credential{allCredentials[len(allCredentials)-2]},
				ResponseType: "delta",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				// Should be empty again
				RemovedIds:   nil,
				EstItemCount: 20,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialsResponse{}, "list_token"),
		),
	)
	req.ListToken = got.ListToken
	// Get the second page
	got, err = s.ListCredentials(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 1)
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialsResponse{
				Items:        []*pb.Credential{allCredentials[len(allCredentials)-1]},
				ResponseType: "complete",
				ListToken:    "",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
				EstItemCount: 20,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialsResponse{}, "list_token"),
		),
	)
	req.ListToken = got.ListToken

	// List items in the empty store
	req = &pbs.ListCredentialsRequest{
		CredentialStoreId: emptyStore.PublicId,
		Filter:            "",
		ListToken:         "",
		PageSize:          2,
	}
	got, err = s.ListCredentials(ctx, req)
	require.NoError(err)
	require.Len(got.GetItems(), 0)
	// Compare without comparing the list token
	assert.Empty(
		cmp.Diff(
			got,
			&pbs.ListCredentialsResponse{
				Items:        nil,
				ResponseType: "complete",
				SortBy:       "created_time",
				SortDir:      "desc",
				RemovedIds:   nil,
			},
			cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}),
			protocmp.Transform(),
			protocmp.IgnoreFields(&pbs.ListCredentialsResponse{}, "list_token"),
		),
	)

	// Create unauthenticated user
	unauthAt := authtoken.TestAuthToken(t, conn, kmsRepo, o.GetPublicId())
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
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kmsRepo, &requestInfo)

	_, err = s.ListCredentials(ctx, &pbs.ListCredentialsRequest{
		CredentialStoreId: credStore.PublicId,
	})
	require.Error(err)
	assert.Equal(handlers.ForbiddenError(), err)
}
