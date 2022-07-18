package credentials

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentials"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var testAuthorizedActions = []string{"no-op", "read", "update", "delete"}

func TestList(t *testing.T) {
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
	store := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	storeNoCreds := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)

	var wantCreds []*pb.Credential
	for i := 0; i < 10; i++ {
		user := fmt.Sprintf("user-%d", i)
		pass := fmt.Sprintf("pass-%d", i)
		c := static.TestUsernamePasswordCredential(t, conn, wrapper, user, pass, store.GetPublicId(), prj.GetPublicId())
		hm, err := crypto.HmacSha256(context.Background(), []byte(pass), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
		require.NoError(t, err)
		wantCreds = append(wantCreds, &pb.Credential{
			Id:                c.GetPublicId(),
			CredentialStoreId: store.GetPublicId(),
			Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
			CreatedTime:       c.GetCreateTime().GetTimestamp(),
			UpdatedTime:       c.GetUpdateTime().GetTimestamp(),
			Version:           c.GetVersion(),
			Type:              credential.UsernamePasswordSubtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Attrs: &pb.Credential_UsernamePasswordAttributes{
				UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
					Username:     wrapperspb.String(c.GetUsername()),
					PasswordHmac: base64.RawURLEncoding.EncodeToString([]byte(hm)),
				},
			},
		})

		spk := static.TestSshPrivateKeyCredential(t, conn, wrapper, user, static.TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId())
		hm, err = crypto.HmacSha256(context.Background(), []byte(static.TestSshPrivateKeyPem), databaseWrapper, []byte(store.GetPublicId()), nil)
		require.NoError(t, err)
		wantCreds = append(wantCreds, &pb.Credential{
			Id:                spk.GetPublicId(),
			CredentialStoreId: store.GetPublicId(),
			Scope:             &scopepb.ScopeInfo{Id: prj.GetPublicId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
			CreatedTime:       spk.GetCreateTime().GetTimestamp(),
			UpdatedTime:       spk.GetUpdateTime().GetTimestamp(),
			Version:           spk.GetVersion(),
			Type:              credential.SshPrivateKeySubtype.String(),
			AuthorizedActions: testAuthorizedActions,
			Attrs: &pb.Credential_SshPrivateKeyAttributes{
				SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
					Username:       wrapperspb.String(c.GetUsername()),
					PrivateKeyHmac: base64.RawURLEncoding.EncodeToString([]byte(hm)),
				},
			},
		})
	}

	cases := []struct {
		name    string
		req     *pbs.ListCredentialsRequest
		res     *pbs.ListCredentialsResponse
		anonRes *pbs.ListCredentialsResponse
		err     error
	}{
		{
			name:    "List many credentials",
			req:     &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId()},
			res:     &pbs.ListCredentialsResponse{Items: wantCreds},
			anonRes: &pbs.ListCredentialsResponse{Items: wantCreds},
		},
		{
			name:    "List no credentials",
			req:     &pbs.ListCredentialsRequest{CredentialStoreId: storeNoCreds.GetPublicId()},
			res:     &pbs.ListCredentialsResponse{},
			anonRes: &pbs.ListCredentialsResponse{},
		},
		{
			name:    "Filter to one credential",
			req:     &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId(), Filter: fmt.Sprintf(`"/item/id"==%q`, wantCreds[1].GetId())},
			res:     &pbs.ListCredentialsResponse{Items: wantCreds[1:2]},
			anonRes: &pbs.ListCredentialsResponse{Items: wantCreds[1:2]},
		},
		{
			name:    "Filter on Attribute",
			req:     &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId(), Filter: fmt.Sprintf(`"/item/attributes/username"==%q`, wantCreds[2].GetUsernamePasswordAttributes().GetUsername().Value)},
			res:     &pbs.ListCredentialsResponse{Items: wantCreds[2:4]},
			anonRes: &pbs.ListCredentialsResponse{}, // anonymous user does not have access to attributes
		},
		{
			name:    "Filter to no credential",
			req:     &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId(), Filter: `"/item/id"=="doesnt match"`},
			res:     &pbs.ListCredentialsResponse{},
			anonRes: &pbs.ListCredentialsResponse{},
		},
		{
			name: "Filter Bad Format",
			req:  &pbs.ListCredentialsRequest{CredentialStoreId: store.GetPublicId(), Filter: `"//id/"=="bad"`},
			err:  handlers.InvalidArgumentErrorf("bad format", nil),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewService(staticRepoFn, iamRepoFn)
			require.NoError(t, err, "Couldn't create new host set service.")

			// Test non-anonymous listing
			got, gErr := s.ListCredentials(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(t, gErr)
				assert.True(t, errors.Is(gErr, tc.err), "ListCredentialStore(%q) got error %v, wanted %v", tc.req, gErr, tc.err)
				return
			}
			require.NoError(t, gErr)
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeated(func(x, y *pb.Credential) bool {
				return x.Id < y.Id
			})))

			// Test anonymous listing
			got, gErr = s.ListCredentials(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), tc.req)
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
	s, err := NewService(staticRepoFn, iamRepoFn)
	require.NoError(t, err)

	upCred := static.TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId())
	upCredPrev := static.TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId(), static.WithPublicId(fmt.Sprintf("%s_1234567890", credential.PreviousUsernamePasswordCredentialPrefix)))
	upHm, err := crypto.HmacSha256(context.Background(), []byte("pass"), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
	require.NoError(t, err)

	spkCred := static.TestSshPrivateKeyCredential(t, conn, wrapper, "user", static.TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId())
	spkHm, err := crypto.HmacSha256(context.Background(), []byte(static.TestSshPrivateKeyPem), databaseWrapper, []byte(store.GetPublicId()), nil)
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
					Scope:             &scopepb.ScopeInfo{Id: store.GetScopeId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
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
					Scope:             &scopepb.ScopeInfo{Id: store.GetScopeId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
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
			name: "success-spk",
			id:   spkCred.GetPublicId(),
			res: &pbs.GetCredentialResponse{
				Item: &pb.Credential{
					Id:                spkCred.GetPublicId(),
					CredentialStoreId: spkCred.GetStoreId(),
					Scope:             &scopepb.ScopeInfo{Id: store.GetScopeId(), Type: scope.Project.String(), ParentScopeId: prj.GetParentId()},
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
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", credential.UsernamePasswordCredentialPrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", static.CredentialStorePrefix),
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
			assert.Empty(t, cmp.Diff(got, tc.res, protocmp.Transform()))

			// Test anonymous get
			got, gErr = s.GetCredential(auth.DisabledAuthTestContext(iamRepoFn, prj.GetPublicId(), auth.WithUserId(auth.AnonymousUserId)), req)
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
	s, err := NewService(staticRepoFn, iamRepoFn)
	require.NoError(t, err)

	upCred := static.TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", store.GetPublicId(), prj.GetPublicId())
	spkCred := static.TestSshPrivateKeyCredential(t, conn, wrapper, "user", static.TestSshPrivateKeyPem, store.GetPublicId(), prj.GetPublicId())

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
			name: "success-spk",
			id:   spkCred.GetPublicId(),
		},
		{
			name: "not found error",
			id:   fmt.Sprintf("%s_1234567890", credential.UsernamePasswordCredentialPrefix),
			err:  handlers.NotFoundError(),
		},
		{
			name: "bad prefix",
			id:   fmt.Sprintf("%s_1234567890", static.CredentialStorePrefix),
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
				Id:                credential.UsernamePasswordCredentialPrefix + "_notallowed",
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
			name: "Must provide password]",
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
			name: "valid",
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
			idPrefix: credential.UsernamePasswordCredentialPrefix + "_",
			res: &pbs.CreateCredentialResponse{
				Uri: fmt.Sprintf("credentials/%s_", credential.UsernamePasswordCredentialPrefix),
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			s, err := NewService(repoFn, iamRepoFn)
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
				databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
				password := tc.req.GetItem().GetUsernamePasswordAttributes().GetPassword().GetValue()
				hm, err := crypto.HmacSha256(context.Background(), []byte(password), databaseWrapper, []byte(store.GetPublicId()), nil, crypto.WithEd25519())
				require.NoError(err)

				// Validate attributes equal
				assert.Equal(tc.req.GetItem().GetUsernamePasswordAttributes().GetUsername().GetValue(),
					got.GetItem().GetUsernamePasswordAttributes().GetUsername().GetValue())
				assert.Equal(base64.RawURLEncoding.EncodeToString([]byte(hm)), got.GetItem().GetUsernamePasswordAttributes().GetPasswordHmac())
				assert.Empty(got.GetItem().GetUsernamePasswordAttributes().GetPassword())

				// Clear attributes for compare below
				got.Item.Attrs = nil

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.Empty(cmp.Diff(got, tc.res, protocmp.Transform(), protocmp.SortRepeatedFields(got)), "CreateCredential(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

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

	s, err := NewService(staticRepoFn, iamRepoFn)
	require.NoError(t, err)

	fieldmask := func(paths ...string) *fieldmaskpb.FieldMask {
		return &fieldmaskpb.FieldMask{Paths: paths}
	}

	store := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())

	freshCred := func(user, pass string) (*static.UsernamePasswordCredential, func()) {
		t.Helper()
		cred := static.TestUsernamePasswordCredential(t, conn, wrapper, user, pass, store.GetPublicId(), prj.GetPublicId())
		clean := func() {
			_, err := s.DeleteCredential(ctx, &pbs.DeleteCredentialRequest{Id: cred.GetPublicId()})
			require.NoError(t, err)
		}
		return cred, clean
	}

	databaseWrapper, err := kkms.GetWrapper(context.Background(), prj.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)

	successCases := []struct {
		name string
		req  *pbs.UpdateCredentialRequest
		res  func(cred *pb.Credential) *pb.Credential
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
			name: "update-username",
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
	}

	for _, tc := range successCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			cred, cleanup := freshCred("user", "pass")
			defer cleanup()

			if tc.req.Item.GetVersion() == 0 {
				tc.req.Item.Version = 1
			}
			if tc.req.GetId() == "" {
				tc.req.Id = cred.GetPublicId()
			}
			resToChange, err := s.GetCredential(ctx, &pbs.GetCredentialRequest{Id: cred.GetPublicId()})
			require.NoError(err)
			want := &pbs.UpdateCredentialResponse{Item: tc.res(resToChange.GetItem())}

			got, gErr := s.UpdateCredential(ctx, tc.req)
			require.NoError(gErr)
			require.NotNil(got)

			gotUpdateTime := got.GetItem().GetUpdatedTime()
			created := cred.GetCreateTime().GetTimestamp()
			assert.True(gotUpdateTime.AsTime().After(created.AsTime()), "Should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

			want.Item.UpdatedTime = got.Item.UpdatedTime

			assert.EqualValues(2, got.Item.Version)
			want.Item.Version = 2

			assert.Empty(cmp.Diff(got, want, protocmp.Transform()))
		})
	}

	// cant update read only fields
	cred, cleanup := freshCred("user", "pass")
	defer cleanup()

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
				Id:         cred.GetPublicId(),
				Item:       tc.item,
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{tc.path}},
			}
			req.Item.Version = cred.Version

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
		})
	}
}
