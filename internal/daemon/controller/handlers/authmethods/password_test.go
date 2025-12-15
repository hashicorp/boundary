// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authmethods_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	am "github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	scopepb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestUpdate_Password(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	authMethodRepoFn := func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(ctx, rw, rw, kms)
	}
	iamRepo := iam.TestRepo(t, conn, wrapper)

	o, _ := iam.TestScopes(t, iamRepo)
	tested, err := authmethods.NewService(ctx, kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn, ldapRepoFn, authMethodRepoFn, 1000)
	require.NoError(t, err, "Error when getting new auth_method service.")

	defaultScopeInfo := &scopepb.ScopeInfo{Id: o.GetPublicId(), Type: o.GetType(), ParentScopeId: scope.Global.String()}

	freshAuthMethod := func() (*pb.AuthMethod, func()) {
		am, err := tested.CreateAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
			&pbs.CreateAuthMethodRequest{Item: &pb.AuthMethod{
				ScopeId:     o.GetPublicId(),
				Name:        wrapperspb.String("default"),
				Description: wrapperspb.String("default"),
				Type:        "password",
			}})
		require.NoError(t, err)

		clean := func() {
			_, err := tested.DeleteAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()),
				&pbs.DeleteAuthMethodRequest{Id: am.GetItem().GetId()})
			require.NoError(t, err)
		}

		return am.GetItem(), clean
	}

	cases := []struct {
		name string
		req  *pbs.UpdateAuthMethodRequest
		res  *pbs.UpdateAuthMethodResponse
		err  error
	}{
		{
			name: "Update an Existing AuthMethod",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinPasswordLength:  8,
							MinLoginNameLength: 3,
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description,type"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinPasswordLength:  8,
							MinLoginNameLength: 3,
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateAuthMethodRequest{
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "No Paths in Mask",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Only non-existent paths in Mask",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistent_field"}},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant change type",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"name", "type"}},
				Item: &pb.AuthMethod{
					Name: &wrapperspb.StringValue{Value: "updated name"},
					Type: "oidc",
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant change is primary",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"is_primary"}},
				Item: &pb.AuthMethod{
					IsPrimary: true,
				},
			},
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.AuthMethod{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinPasswordLength:  8,
							MinLoginNameLength: 3,
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinPasswordLength:  8,
							MinLoginNameLength: 3,
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinPasswordLength:  8,
							MinLoginNameLength: 3,
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Update a Non Existing AuthMethod",
			req: &pbs.UpdateAuthMethodRequest{
				Id: globals.PasswordAuthMethodPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			err: handlers.ApiErrorWithCode(codes.NotFound),
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.AuthMethod{
					Id:          globals.PasswordAuthMethodPrefix + "_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.AuthMethod{
					CreatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.AuthMethod{
					UpdatedTime: timestamppb.Now(),
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Cant specify Type",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"type"},
				},
				Item: &pb.AuthMethod{
					Type: "oidc",
				},
			},
			res: nil,
			err: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "Update login name length",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.min_login_name_length"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinLoginNameLength: 42,
							MinPasswordLength:  55555,
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinPasswordLength:  8,
							MinLoginNameLength: 42,
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
		{
			name: "Update password length",
			req: &pbs.UpdateAuthMethodRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"attributes.min_password_length"},
				},
				Item: &pb.AuthMethod{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinLoginNameLength: 5555,
							MinPasswordLength:  42,
						},
					},
				},
			},
			res: &pbs.UpdateAuthMethodResponse{
				Item: &pb.AuthMethod{
					ScopeId:     o.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "default"},
					Type:        "password",
					Attrs: &pb.AuthMethod_PasswordAuthMethodAttributes{
						PasswordAuthMethodAttributes: &pb.PasswordAuthMethodAttributes{
							MinPasswordLength:  42,
							MinLoginNameLength: 3,
						},
					},
					Scope:                       defaultScopeInfo,
					AuthorizedActions:           pwAuthorizedActions,
					AuthorizedCollectionActions: authorizedCollectionActions,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			am, cleanup := freshAuthMethod()
			defer cleanup()

			tc.req.Item.Version = 1

			if tc.req.GetId() == "" {
				tc.req.Id = am.GetId()
			}

			if tc.res != nil && tc.res.Item != nil {
				tc.res.Item.Id = am.GetId()
				tc.res.Item.CreatedTime = am.GetCreatedTime()
			}

			got, gErr := tested.UpdateAuthMethod(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), tc.req)
			if tc.err != nil {
				require.Error(gErr)
				assert.True(errors.Is(gErr, tc.err), "UpdateAuthMethod(%+v) got error %v, wanted %v", tc.req, gErr, tc.err)
			}

			if tc.res == nil {
				require.Nil(got)
			}

			cmpOptions := []cmp.Option{
				protocmp.Transform(),
				cmpopts.SortSlices(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b protocmp.Message) bool {
					return a.String() < b.String()
				}),
			}
			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateAuthMethod response to be nil, but was %v", got)

				created := am.GetCreatedTime().AsTime()
				gotUpdateTime := got.GetItem().GetUpdatedTime().AsTime()
				// Verify it is a auth_method updated after it was created
				assert.True(gotUpdateTime.After(created), "Updated auth_method should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, created)

				// Ignore all values which are hard to compare against.
				cmpOptions = append(cmpOptions, protocmp.IgnoreFields(&pb.AuthMethod{}, "updated_time"))

				assert.EqualValues(2, got.Item.Version)
				tc.res.Item.Version = 2
			}
			assert.Empty(cmp.Diff(got, tc.res, cmpOptions...), "UpdateAuthMethod(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestAuthenticate_Password(t *testing.T) {
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	authMethodRepoFn := func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(ctx, rw, rw, kms)
	}
	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]

	iam.TestSetPrimaryAuthMethod(t, iam.TestRepo(t, conn, wrapper), o, am.PublicId)

	acct, err := password.NewAccount(ctx, am.GetPublicId(), password.WithLoginName(testLoginName))
	require.NoError(t, err)

	pwRepo, err := pwRepoFn()
	require.NoError(t, err)
	acct, err = pwRepo.CreateAccount(context.Background(), o.GetPublicId(), acct, password.WithPassword(testPassword))
	require.NoError(t, err)
	require.NotNil(t, acct)

	c := event.TestEventerConfig(t, "Test_StartAuth_to_Callback", event.TestWithObservationSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	c.EventerConfig.TelemetryEnabled = true
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "use-Test_Authenticate", event.WithEventerConfig(&c.EventerConfig)))
	sinkFileName := c.ObservationEvents.Name()
	t.Cleanup(func() {
		require.NoError(t, os.Remove(sinkFileName))
	})

	cases := []struct {
		name            string
		request         *pbs.AuthenticateRequest
		actions         []string
		wantType        string
		wantErr         error
		wantErrContains string
	}{
		{
			name: "basic",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
					PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantType: "token",
		},
		{
			name: "cookie-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "cookie",
				Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
					PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantType: "cookie",
		},
		{
			name: "no-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
					PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
		},
		{
			name: "bad-token-type",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "email",
				Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
					PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "no-authmethod",
			request: &pbs.AuthenticateRequest{
				Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
					PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.InvalidArgument),
		},
		{
			name: "wrong-password",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
					PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
						LoginName: testLoginName,
						Password:  "wrong",
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
		{
			name: "wrong-login-name",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
					PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
						LoginName: "wrong",
						Password:  testPassword,
					},
				},
			},
			wantErr: handlers.ApiErrorWithCode(codes.Unauthenticated),
		},
		{
			name: "no-attributes",
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Attrs:        &pbs.AuthenticateRequest_PasswordLoginAttributes{},
			},
			wantErr:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: `Details: {{name: "attributes", desc: "This is a required field."}}`,
		},
		{
			name:    "with-callback-action",
			actions: []string{"callback"},
			request: &pbs.AuthenticateRequest{
				AuthMethodId: am.GetPublicId(),
				TokenType:    "token",
				Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
					PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
						LoginName: testLoginName,
						Password:  testPassword,
					},
				},
			},
			wantErr:         handlers.ApiErrorWithCode(codes.InvalidArgument),
			wantErrContains: `Details: {{name: "request_path", desc: "callback is not a valid action for this auth method."}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s, err := authmethods.NewService(ctx, kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn, ldapRepoFn, authMethodRepoFn, 1000)
			require.NoError(err)

			resp, err := s.Authenticate(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId(), auth.WithActions(tc.actions)), tc.request)
			if tc.wantErr != nil {
				assert.Error(err)
				assert.Truef(errors.Is(err, tc.wantErr), "Got %#v, wanted %#v", err, tc.wantErr)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)

			aToken := resp.GetAuthTokenResponse()
			assert.NotEmpty(aToken.GetId())
			assert.NotEmpty(aToken.GetToken())
			assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
			assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetUpdatedTime())
			assert.Equal(aToken.GetCreatedTime(), aToken.GetApproximateLastUsedTime())
			assert.Equal(acct.GetPublicId(), aToken.GetAccountId())
			assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
			assert.Equal(tc.wantType, resp.GetType())

			defer func() { _ = os.WriteFile(sinkFileName, nil, 0o666) }()
			b, err := os.ReadFile(sinkFileName)
			require.NoError(err)
			gotRes := &cloudevents.Event{}
			err = json.Unmarshal(b, gotRes)
			require.NoErrorf(err, "json: %s", string(b))
			details, ok := gotRes.Data.(map[string]any)["details"]
			require.True(ok)
			for _, key := range details.([]any) {
				assert.Contains(key.(map[string]any)["payload"], "user_id")
				assert.Contains(key.(map[string]any)["payload"], "auth_token_start")
				assert.Contains(key.(map[string]any)["payload"], "auth_token_end")
			}
		})
	}
}

func TestAuthenticate_AuthAccountConnectedToIamUser_Password(t *testing.T) {
	ctx := context.TODO()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	o, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	iamRepoFn := func() (*iam.Repository, error) {
		return iam.TestRepo(t, conn, wrapper), nil
	}
	oidcRepoFn := func() (*oidc.Repository, error) {
		return oidc.NewRepository(ctx, rw, rw, kms)
	}
	ldapRepoFn := func() (*ldap.Repository, error) {
		return ldap.NewRepository(ctx, rw, rw, kms)
	}
	pwRepoFn := func() (*password.Repository, error) {
		return password.NewRepository(ctx, rw, rw, kms)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	authMethodRepoFn := func() (*am.AuthMethodRepository, error) {
		return am.NewAuthMethodRepository(ctx, rw, rw, kms)
	}

	am := password.TestAuthMethods(t, conn, o.GetPublicId(), 1)[0]
	acct, err := password.NewAccount(ctx, am.GetPublicId(), password.WithLoginName(testLoginName))
	require.NoError(err)

	pwRepo, err := pwRepoFn()
	require.NoError(err)
	acct, err = pwRepo.CreateAccount(context.Background(), o.GetPublicId(), acct, password.WithPassword(testPassword))
	require.NoError(err)

	// connected to an account.
	iamRepo, err := iamRepoFn()
	require.NoError(err)
	iam.TestUser(t, iamRepo, am.ScopeId, iam.WithAccountIds(acct.PublicId))
	iamUser, err := iamRepo.LookupUserWithLogin(context.Background(), acct.GetPublicId())
	require.NoError(err)

	s, err := authmethods.NewService(ctx, kms, pwRepoFn, oidcRepoFn, iamRepoFn, atRepoFn, ldapRepoFn, authMethodRepoFn, 1000)
	require.NoError(err)
	resp, err := s.Authenticate(auth.DisabledAuthTestContext(iamRepoFn, o.GetPublicId()), &pbs.AuthenticateRequest{
		AuthMethodId: am.GetPublicId(),
		Attrs: &pbs.AuthenticateRequest_PasswordLoginAttributes{
			PasswordLoginAttributes: &pbs.PasswordLoginAttributes{
				LoginName: testLoginName,
				Password:  testPassword,
			},
		},
	})
	require.NoError(err)

	aToken := resp.GetAuthTokenResponse()
	assert.Equal(iamUser.GetPublicId(), aToken.GetUserId())
	assert.Equal(am.GetPublicId(), aToken.GetAuthMethodId())
	assert.Equal(acct.GetPublicId(), aToken.GetAccountId())

	assert.NotEmpty(aToken.GetId())
	assert.NotEmpty(aToken.GetToken())
	assert.True(strings.HasPrefix(aToken.GetToken(), aToken.GetId()))
}
