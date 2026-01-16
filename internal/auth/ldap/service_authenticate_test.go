// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/jimlambrt/gldap/testdirectory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticate(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	rootWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, rootWrapper)
	opt := event.TestWithObservationSink(t)
	c := event.TestEventerConfig(t, "Test_StartAuth_to_Callback", opt)
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	c.EventerConfig.TelemetryEnabled = true
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "use-Test_Authenticate", event.WithEventerConfig(&c.EventerConfig)))
	// some standard factories for unit tests
	authenticatorFn := func() (Authenticator, error) {
		return NewRepository(testCtx, testRw, testRw, testKms)
	}
	lookupUserWithFn := func() (LookupUser, error) {
		return iam.NewRepository(testCtx, testRw, testRw, testKms)
	}
	tokenCreatorFn := func() (AuthTokenCreator, error) {
		return authtoken.NewRepository(testCtx, testRw, testRw, testKms)
	}
	iamRepo := iam.TestRepo(t, testConn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)
	orgDbWrapper, err := testKms.GetWrapper(testCtx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Error,
	})
	td := testdirectory.Start(t,
		testdirectory.WithDefaults(t, &testdirectory.Defaults{AllowAnonymousBind: true}),
		testdirectory.WithLogger(t, logger),
	)
	tdCerts, err := ParseCertificates(testCtx, td.Cert())
	require.NoError(t, err)

	groups := []*gldap.Entry{
		testdirectory.NewGroup(t, "admin", []string{"alice"}),
	}
	users := testdirectory.NewUsers(t, []string{"alice", "bob"}, testdirectory.WithMembersOf(t, "admin"))
	td.SetUsers(users...)
	td.SetGroups(groups...)

	testPrimaryAuthMethod := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId,
		[]string{fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port())},
		WithCertificates(testCtx, tdCerts...),
		WithDiscoverDn(testCtx),
		WithEnableGroups(testCtx),
		WithUserDn(testCtx, testdirectory.DefaultUserDN),
		WithGroupDn(testCtx, testdirectory.DefaultGroupDN),
	)
	iam.TestSetPrimaryAuthMethod(t, iamRepo, org, testPrimaryAuthMethod.PublicId)

	testNotPrimaryAuthMethod := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId,
		[]string{fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port())},
		WithCertificates(testCtx, tdCerts...),
		WithDiscoverDn(testCtx),
		WithEnableGroups(testCtx),
		WithUserDn(testCtx, testdirectory.DefaultUserDN),
		WithGroupDn(testCtx, testdirectory.DefaultGroupDN),
	)

	const (
		testLoginName  = "alice"
		testPassword   = "password"
		testLoginName2 = "bob"
	)

	testExistingAcct := TestAccount(t, testConn, testNotPrimaryAuthMethod, testLoginName2)
	iam.TestUser(t, iamRepo, org.PublicId, iam.WithAccountIds(testExistingAcct.PublicId))

	// order is important in these tests, so we're using a slice
	tests := []struct {
		order                 int
		name                  string
		ctx                   context.Context
		authenticatorFn       AuthenticatorFactory
		lookupUserWithLoginFn LookupUserFactory
		tokenCreatorFn        AuthTokenCreatorFactory
		authMethodId          string
		loginName             string
		password              string
		wantErrMatch          *errors.Template
		wantErrContains       string
	}{
		{
			order:                 0,
			name:                  "success-with-primary-auth-method-auto-create",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			authMethodId:          testPrimaryAuthMethod.PublicId,
			loginName:             testLoginName,
			password:              testPassword,
		},
		{
			order:                 1,
			name:                  "success-with-primary-auth-method-existing-account",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			authMethodId:          testPrimaryAuthMethod.PublicId,
			loginName:             testLoginName,
			password:              testPassword,
		},
		{
			order:                 2,
			name:                  "success-with-non-primary-auth-method",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			authMethodId:          testNotPrimaryAuthMethod.PublicId,
			loginName:             testLoginName2,
			password:              testPassword,
		},
		{
			order:                 3,
			name:                  "err-not-primary-refused-to-create-user",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			authMethodId:          testNotPrimaryAuthMethod.PublicId,
			loginName:             testLoginName,
			password:              testPassword,
			wantErrMatch:          errors.T(errors.RecordNotFound),
			wantErrContains:       "auth method is not primary for the scope so refusing to auto-create user",
		},
		{
			order:                 4,
			name:                  "missing-authenticator-fn",
			ctx:                   testCtx,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			authMethodId:          testNotPrimaryAuthMethod.PublicId,
			loginName:             testLoginName,
			password:              testPassword,
			wantErrMatch:          errors.T(errors.InvalidParameter),
			wantErrContains:       "missing authenticator factory",
		},
		{
			order:           5,
			name:            "missing-lookup-user-fn",
			ctx:             testCtx,
			authenticatorFn: authenticatorFn,
			tokenCreatorFn:  tokenCreatorFn,
			authMethodId:    testNotPrimaryAuthMethod.PublicId,
			loginName:       testLoginName,
			password:        testPassword,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing lookup user factory",
		},
		{
			order:                 6,
			name:                  "missing-at-creator-fn",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			authMethodId:          testNotPrimaryAuthMethod.PublicId,
			loginName:             testLoginName,
			password:              testPassword,
			wantErrMatch:          errors.T(errors.InvalidParameter),
			wantErrContains:       "missing auth token creator factory",
		},
		{
			order:                 7,
			name:                  "missing-auth-method-id",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			loginName:             testLoginName,
			password:              testPassword,
			wantErrMatch:          errors.T(errors.InvalidParameter),
			wantErrContains:       "missing auth method id",
		},
		{
			order:                 8,
			name:                  "missing-login-name",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			authMethodId:          testNotPrimaryAuthMethod.PublicId,
			password:              testPassword,
			wantErrMatch:          errors.T(errors.InvalidParameter),
			wantErrContains:       "missing login name",
		},
		{
			order:                 9,
			name:                  "missing-password",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			authMethodId:          testNotPrimaryAuthMethod.PublicId,
			loginName:             testLoginName,
			wantErrMatch:          errors.T(errors.InvalidParameter),
			wantErrContains:       "missing password",
		},
		{
			order: 10,
			name:  "authenticator-fn-err",
			ctx:   testCtx,
			authenticatorFn: func() (Authenticator, error) {
				return nil, errors.New(testCtx, errors.Internal, "test", "authenticator-fn-err")
			},
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			authMethodId:          testPrimaryAuthMethod.PublicId,
			loginName:             testLoginName,
			password:              testPassword,
			wantErrMatch:          errors.T(errors.Internal),
			wantErrContains:       "authenticator-fn-err",
		},
		{
			order:           11,
			name:            "lookup-user-fn-err",
			ctx:             testCtx,
			authenticatorFn: authenticatorFn,
			lookupUserWithLoginFn: func() (LookupUser, error) {
				return nil, errors.New(testCtx, errors.Internal, "test", "lookup-user-fn-err")
			},
			tokenCreatorFn:  tokenCreatorFn,
			authMethodId:    testPrimaryAuthMethod.PublicId,
			loginName:       testLoginName,
			password:        testPassword,
			wantErrMatch:    errors.T(errors.Internal),
			wantErrContains: "lookup-user-fn-err",
		},
		{
			order:                 12,
			name:                  "at-fn-err",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn: func() (AuthTokenCreator, error) {
				return nil, errors.New(testCtx, errors.Internal, "test", "at-fn-err")
			},
			authMethodId:    testPrimaryAuthMethod.PublicId,
			loginName:       testLoginName,
			password:        testPassword,
			wantErrMatch:    errors.T(errors.Internal),
			wantErrContains: "at-fn-err",
		},
		{
			order: 13,
			name:  "authenticate-err",
			ctx:   testCtx,
			authenticatorFn: func() (Authenticator, error) {
				return &mockAuthenticator{authErr: errors.New(testCtx, errors.Internal, "test", "authenticate-err")}, nil
			},
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn:        tokenCreatorFn,
			authMethodId:          testPrimaryAuthMethod.PublicId,
			loginName:             testLoginName,
			password:              testPassword,
			wantErrMatch:          errors.T(errors.Internal),
			wantErrContains:       "authenticate-err",
		},
		{
			order:                 14,
			name:                  "token-err",
			ctx:                   testCtx,
			authenticatorFn:       authenticatorFn,
			lookupUserWithLoginFn: lookupUserWithFn,
			tokenCreatorFn: func() (AuthTokenCreator, error) {
				return &mockTokenCreator{tokenErr: errors.New(testCtx, errors.Internal, "test", "token-err")}, nil
			},
			authMethodId:    testPrimaryAuthMethod.PublicId,
			loginName:       testLoginName,
			password:        testPassword,
			wantErrMatch:    errors.T(errors.Internal),
			wantErrContains: "token-err",
		},
	}
	for idx, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.Equal(tc.order, idx)
			got, err := Authenticate(tc.ctx, tc.authenticatorFn, tc.lookupUserWithLoginFn, tc.tokenCreatorFn, tc.authMethodId, tc.loginName, tc.password)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Empty(got)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "unexpected error")
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotEmpty(got)
			sinkFileName := c.ObservationEvents.Name()
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

type mockAuthenticator struct {
	authErr error
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, authMethodId, loginName, password string) (*Account, error) {
	return nil, m.authErr
}

type mockTokenCreator struct {
	tokenErr error
}

func (m *mockTokenCreator) CreateAuthToken(ctx context.Context, withIamUser *iam.User, withAuthAccountId string, opt ...authtoken.Option) (*authtoken.AuthToken, error) {
	return nil, m.tokenErr
}
