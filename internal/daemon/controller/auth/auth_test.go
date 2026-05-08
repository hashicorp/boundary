// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/event"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/tests/api"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthTokenAuthenticator(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	tokenRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	encToken, err := authtoken.EncryptToken(context.Background(), kms, o.GetPublicId(), at.GetPublicId(), at.GetToken())
	require.NoError(t, err)

	tokValue := at.GetPublicId() + "_" + encToken
	jsCookieVal, httpCookieVal := tokValue[:len(tokValue)/2], tokValue[len(tokValue)/2:]

	cases := []struct {
		name        string
		headers     map[string]string
		cookies     []http.Cookie
		userId      string
		tokenFormat TokenFormat
	}{
		{
			name:        "Empty headers",
			headers:     map[string]string{},
			tokenFormat: AuthTokenTypeUnknown,
		},
		{
			name:        "Bearer token",
			headers:     map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			userId:      at.GetIamUserId(),
			tokenFormat: AuthTokenTypeBearer,
		},
		{
			name: "Split cookie token",
			cookies: []http.Cookie{
				{Name: handlers.HttpOnlyCookieName, Value: httpCookieVal},
				{Name: handlers.JsVisibleCookieName, Value: jsCookieVal},
			},
			userId:      at.GetIamUserId(),
			tokenFormat: AuthTokenTypeSplitCookie,
		},
		{
			name: "Split cookie token only http cookie",
			cookies: []http.Cookie{
				{Name: handlers.HttpOnlyCookieName, Value: httpCookieVal},
			},
			tokenFormat: AuthTokenTypeUnknown,
		},
		{
			name: "Split cookie token only js cookie",
			cookies: []http.Cookie{
				{Name: handlers.JsVisibleCookieName, Value: jsCookieVal},
			},
			tokenFormat: AuthTokenTypeUnknown,
		},
		{
			name:    "Cookie and auth header",
			headers: map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			cookies: []http.Cookie{
				{Name: handlers.HttpOnlyCookieName, Value: httpCookieVal},
				{Name: handlers.JsVisibleCookieName, Value: jsCookieVal},
			},
			userId:      at.GetIamUserId(),
			tokenFormat: AuthTokenTypeBearer,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://127.0.0.1/v1/scopes/o_1", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			for _, c := range tc.cookies {
				req.AddCookie(&c)
			}

			// Add values for authn/authz checking
			requestInfo := authpb.RequestInfo{
				Path:   req.URL.Path,
				Method: req.Method,
			}
			requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = GetTokenFromRequest(context.TODO(), kms, req)
			assert.Equal(t, uint32(tc.tokenFormat), requestInfo.TokenFormat)

			if tc.userId == "" {
				return
			}
			ctx := NewVerifierContext(context.Background(), iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

			v, ok := ctx.Value(verifierKey).(*verifier)
			require.True(t, ok)
			require.NotNil(t, v)

			v.decryptToken(context.TODO())

			at, err := tokenRepo.ValidateToken(ctx, v.requestInfo.PublicId, v.requestInfo.Token)
			require.NoError(t, err)
			assert.Equal(t, tc.userId, at.GetIamUserId())
		})
	}
}

func TestVerify_RedactedAuth_AuditEvent(t *testing.T) {
	ctx := context.Background()
	eventConfig := event.TestEventerConfig(t, "Test_Verify", event.TestWithAuditSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "Test_Verify", event.WithEventerConfig(&eventConfig.EventerConfig)))

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	tokenRepo, err := authtoken.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, testKms)
	}

	o, _ := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, testKms, o.GetPublicId())
	encToken, err := authtoken.EncryptToken(context.Background(), testKms, o.GetPublicId(), at.GetPublicId(), at.GetToken())
	require.NoError(t, err)

	tokValue := at.GetPublicId() + "_" + encToken
	jsCookieVal, httpCookieVal := tokValue[:len(tokValue)/2], tokValue[len(tokValue)/2:]

	tests := []struct {
		name              string
		headers           map[string]string
		cookies           []http.Cookie
		opt               []Option
		disableAuth       bool
		wantResults       VerifyResults
		wantAuthAuditData bool
		wantUserId        string
	}{
		{
			name:              "bearer-token",
			headers:           map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			opt:               []Option{WithScopeId(o.PublicId)},
			wantAuthAuditData: true,
			wantUserId:        at.IamUserId,
		},
		{
			name: "split-cookie-token",
			cookies: []http.Cookie{
				{Name: handlers.HttpOnlyCookieName, Value: httpCookieVal},
				{Name: handlers.JsVisibleCookieName, Value: jsCookieVal},
			},
			opt:               []Option{WithScopeId(o.PublicId)},
			wantAuthAuditData: true,
			wantUserId:        at.IamUserId,
		},
		{
			name:              "no-auth-data",
			opt:               []Option{WithScopeId(o.PublicId)},
			wantAuthAuditData: true,
			wantUserId:        globals.AnonymousUserId,
		},
		{
			name:              "disable-auth",
			opt:               []Option{WithScopeId(o.PublicId)},
			disableAuth:       true,
			wantAuthAuditData: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := httptest.NewRequest("GET", "http://127.0.0.1/v1/scopes/o_1", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			for _, c := range tt.cookies {
				req.AddCookie(&c)
			}

			// Add values for authn/authz checking
			requestInfo := authpb.RequestInfo{
				Path:                req.URL.Path,
				Method:              req.Method,
				DisableAuthEntirely: tt.disableAuth,
			}
			requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = GetTokenFromRequest(context.TODO(), testKms, req)

			ctx := NewVerifierContext(ctx, iamRepoFn, tokenRepoFn, serversRepoFn, testKms, &requestInfo)

			_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
			_ = Verify(ctx, resource.Scope, tt.opt...)
			got := api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

			if tt.wantAuthAuditData {
				auth, ok := got.Data.(map[string]any)["auth"].(map[string]any)
				require.True(ok)
				assert.Equal(encrypt.RedactedData, auth["email"])
				assert.Equal(encrypt.RedactedData, auth["name"])

				if tt.disableAuth {
					assert.Equal(true, auth["disabled_auth_entirely"])
				}
				if tt.wantUserId != "" {
					userInfo, ok := auth["user_info"].(map[string]any)
					require.True(ok)
					assert.Equal(tt.wantUserId, userInfo["id"])
				}
			}
		})
	}
}

func TestVerify_UnredactedLdapAuth_AuditEvent(t *testing.T) {
	ctx := context.Background()
	eventConfig := event.TestEventerConfig(t, "Test_Verify", event.TestWithAuditSink(t))

	// Disable redaction so we can assert on actual values
	for _, sink := range eventConfig.EventerConfig.Sinks {
		if sink.AuditConfig != nil {
			sink.AuditConfig.FilterOverrides = event.AuditFilterOperations{
				event.SensitiveClassification: event.NoOperation,
			}
		}
	}

	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "Test_Verify", event.WithEventerConfig(&eventConfig.EventerConfig)))

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	tokenRepo, err := authtoken.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, testKms)
	}

	// ok lets create a LDAP auth token
	o, _ := iam.TestScopes(t, iamRepo)
	databaseWrapper, err := testKms.GetWrapper(ctx, o.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := ldap.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), []string{"ldaps://ldap1"})
	ldapAcct := ldap.TestAccount(t, conn, testAuthMethod, "freyja",
		ldap.WithFullName(ctx, "Freyja Happy Doggo"),
		ldap.WithEmail(ctx, "you@hellothere.com"),
	)
	foundLdapAcct := ldap.AllocAccount()
	foundLdapAcct.PublicId = ldapAcct.GetPublicId()
	require.NoError(t, rw.LookupById(ctx, foundLdapAcct))
	require.Equal(t, "Freyja Happy Doggo", foundLdapAcct.FullName)
	require.Equal(t, "you@hellothere.com", foundLdapAcct.Email)

	user := iam.TestUser(t, iamRepo, o.GetPublicId())
	_, err = iamRepo.AddUserAccounts(ctx, user.PublicId, user.Version, []string{ldapAcct.GetPublicId()})
	require.NoError(t, err)

	// set ldap auth method as primary
	s, err := iamRepo.LookupScope(ctx, o.PublicId)
	require.NoError(t, err)
	iam.TestSetPrimaryAuthMethod(t, iamRepo, s, testAuthMethod.GetPublicId())

	// ok lets verify we have a fullName and email to populated in the user
	lookedUpUser, _, err := iamRepo.LookupUser(ctx, user.PublicId)
	require.NoError(t, err)
	require.Equal(t, "Freyja Happy Doggo", lookedUpUser.FullName)
	require.Equal(t, "you@hellothere.com", lookedUpUser.Email)

	at, err := tokenRepo.CreateAuthToken(ctx, user, ldapAcct.GetPublicId())
	require.NoError(t, err)
	encToken, err := authtoken.EncryptToken(context.Background(), testKms, o.GetPublicId(), at.GetPublicId(), at.GetToken())
	require.NoError(t, err)

	tokValue := at.GetPublicId() + "_" + encToken
	jsCookieVal, httpCookieVal := tokValue[:len(tokValue)/2], tokValue[len(tokValue)/2:]

	tests := []struct {
		name              string
		headers           map[string]string
		cookies           []http.Cookie
		opt               []Option
		disableAuth       bool
		disableAuthzFails bool
		wantResults       VerifyResults
		wantUserId        string
		wantNameEmail     bool
	}{
		{
			name:          "bearer-token",
			headers:       map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			opt:           []Option{WithScopeId(o.PublicId)},
			wantUserId:    at.IamUserId,
			wantNameEmail: true,
		},
		{
			name: "split-cookie-token",
			cookies: []http.Cookie{
				{Name: handlers.HttpOnlyCookieName, Value: httpCookieVal},
				{Name: handlers.JsVisibleCookieName, Value: jsCookieVal},
			},
			opt:           []Option{WithScopeId(o.PublicId)},
			wantUserId:    at.IamUserId,
			wantNameEmail: true,
		},
		{
			name:       "no-auth-data",
			opt:        []Option{WithScopeId(o.PublicId)},
			wantUserId: globals.AnonymousUserId,
		},
		{
			name:        "disable-auth",
			opt:         []Option{WithScopeId(o.PublicId)},
			disableAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := httptest.NewRequest("GET", "http://127.0.0.1/v1/scopes/o_1", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			for _, c := range tt.cookies {
				req.AddCookie(&c)
			}

			// Add values for authn/authz checking
			requestInfo := authpb.RequestInfo{
				Path:                 req.URL.Path,
				Method:               req.Method,
				DisableAuthEntirely:  tt.disableAuth,
				DisableAuthzFailures: true, // we skipped giving grants so disable authz
			}
			requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = GetTokenFromRequest(context.TODO(), testKms, req)

			ctx := NewVerifierContext(ctx, iamRepoFn, tokenRepoFn, serversRepoFn, testKms, &requestInfo)

			_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
			_ = Verify(ctx, resource.Scope, tt.opt...)
			got := api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

			auth, ok := got.Data.(map[string]any)["auth"].(map[string]any)
			require.True(ok)

			if tt.wantNameEmail {
				assert.Equal("Freyja Happy Doggo", auth["name"])
				assert.Equal("you@hellothere.com", auth["email"])
			} else {
				assert.Nil(auth["name"])
				assert.Nil(auth["email"])
			}

			if tt.disableAuth {
				assert.Equal(true, auth["disabled_auth_entirely"])
			}
			if tt.wantUserId != "" {
				userInfo, ok := auth["user_info"].(map[string]any)
				require.True(ok)
				assert.Equal(tt.wantUserId, userInfo["id"])
			}
		})
	}
}

func TestVerify_UnredactedOidcAuth_AuditEvent(t *testing.T) {
	ctx := context.Background()
	eventConfig := event.TestEventerConfig(t, "Test_Verify", event.TestWithAuditSink(t))

	// Disable redaction so we can assert on actual values
	for _, sink := range eventConfig.EventerConfig.Sinks {
		if sink.AuditConfig != nil {
			sink.AuditConfig.FilterOverrides = event.AuditFilterOperations{
				event.SensitiveClassification: event.NoOperation,
			}
		}
	}

	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "Test_Verify", event.WithEventerConfig(&eventConfig.EventerConfig)))

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	tokenRepo, err := authtoken.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, testKms)
	}

	// ok lets create a OIDC auth token
	o, _ := iam.TestScopes(t, iamRepo)
	databaseWrapper, err := testKms.GetWrapper(ctx, o.GetPublicId(), kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := oidc.TestAuthMethod(t, conn, databaseWrapper, o.GetPublicId(), oidc.ActivePrivateState,
		"alice-rp", "fido",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://hellothere.com")[0]),
		oidc.WithSigningAlgs(oidc.RS256),
		oidc.WithApiUrl(oidc.TestConvertToUrls(t, "http://localhost")[0]),
	)
	oidcAcct := oidc.TestAccount(t, conn, testAuthMethod, "Freyja",
		oidc.WithFullName("Freyja Good Doggo"),
		oidc.WithEmail("me@hellothere.com"),
	)

	user := iam.TestUser(t, iamRepo, o.GetPublicId())
	_, err = iamRepo.AddUserAccounts(ctx, user.PublicId, user.Version, []string{oidcAcct.GetPublicId()})
	require.NoError(t, err)

	s, err := iamRepo.LookupScope(ctx, o.PublicId)
	require.NoError(t, err)

	// set oidcg auth method as primary
	iam.TestSetPrimaryAuthMethod(t, iamRepo, s, testAuthMethod.GetPublicId())

	// ok lets verify we have a fullName and email to populated in the user
	lookedUpUser, _, err := iamRepo.LookupUser(ctx, user.PublicId)
	require.NoError(t, err)
	require.Equal(t, "Freyja Good Doggo", lookedUpUser.FullName)
	require.Equal(t, "me@hellothere.com", lookedUpUser.Email)

	at, err := tokenRepo.CreateAuthToken(ctx, user, oidcAcct.GetPublicId())
	require.NoError(t, err)
	encToken, err := authtoken.EncryptToken(context.Background(), testKms, o.GetPublicId(), at.GetPublicId(), at.GetToken())
	require.NoError(t, err)

	tokValue := at.GetPublicId() + "_" + encToken
	jsCookieVal, httpCookieVal := tokValue[:len(tokValue)/2], tokValue[len(tokValue)/2:]

	tests := []struct {
		name              string
		headers           map[string]string
		cookies           []http.Cookie
		opt               []Option
		disableAuth       bool
		disableAuthzFails bool
		wantResults       VerifyResults
		wantUserId        string
		wantNameEmail     bool
	}{
		{
			name:          "bearer-token",
			headers:       map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			opt:           []Option{WithScopeId(o.PublicId)},
			wantUserId:    at.IamUserId,
			wantNameEmail: true,
		},
		{
			name: "split-cookie-token",
			cookies: []http.Cookie{
				{Name: handlers.HttpOnlyCookieName, Value: httpCookieVal},
				{Name: handlers.JsVisibleCookieName, Value: jsCookieVal},
			},
			opt:           []Option{WithScopeId(o.PublicId)},
			wantUserId:    at.IamUserId,
			wantNameEmail: true,
		},
		{
			name:       "no-auth-data",
			opt:        []Option{WithScopeId(o.PublicId)},
			wantUserId: globals.AnonymousUserId,
		},
		{
			name:        "disable-auth",
			opt:         []Option{WithScopeId(o.PublicId)},
			disableAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			req := httptest.NewRequest("GET", "http://127.0.0.1/v1/scopes/o_1", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			for _, c := range tt.cookies {
				req.AddCookie(&c)
			}

			// Add values for authn/authz checking
			requestInfo := authpb.RequestInfo{
				Path:                 req.URL.Path,
				Method:               req.Method,
				DisableAuthEntirely:  tt.disableAuth,
				DisableAuthzFailures: true, // we skipped giving grants so disable authz
			}
			requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = GetTokenFromRequest(context.TODO(), testKms, req)

			ctx := NewVerifierContext(ctx, iamRepoFn, tokenRepoFn, serversRepoFn, testKms, &requestInfo)

			_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
			_ = Verify(ctx, resource.Scope, tt.opt...)
			got := api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

			auth, ok := got.Data.(map[string]any)["auth"].(map[string]any)
			require.True(ok)

			if tt.wantNameEmail {
				assert.Equal("Freyja Good Doggo", auth["name"])
				assert.Equal("me@hellothere.com", auth["email"])
			} else {
				assert.Nil(auth["name"])
				assert.Nil(auth["email"])
			}

			if tt.disableAuth {
				assert.Equal(true, auth["disabled_auth_entirely"])
			}
			if tt.wantUserId != "" {
				userInfo, ok := auth["user_info"].(map[string]any)
				require.True(ok)
				assert.Equal(tt.wantUserId, userInfo["id"])
			}
		})
	}
}

func TestGrantsHash(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	tokenRepo, err := authtoken.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iamRepo)
	resourceType := resource.Scope
	req := httptest.NewRequest("GET", "http://127.0.0.1/v1/scopes/"+o.GetPublicId(), nil)

	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	encToken, err := authtoken.EncryptToken(context.Background(), kms, o.GetPublicId(), at.GetPublicId(), at.GetToken())
	require.NoError(t, err)
	tokValue := at.GetPublicId() + "_" + encToken

	// Add values for authn/authz checking
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokValue))
	requestInfo := authpb.RequestInfo{
		Path:   req.URL.Path,
		Method: req.Method,
	}
	requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = GetTokenFromRequest(context.TODO(), kms, req)
	verifierCtx := NewVerifierContext(ctx, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	// Create auth result from token
	res := Verify(verifierCtx, resourceType, WithScopeId(o.GetPublicId()))
	hash1, err := res.GrantsHash(ctx)
	require.NoError(t, err)

	// Look up the user and create a second token
	user, _, err := iamRepo.LookupUser(ctx, at.IamUserId)
	require.NoError(t, err)
	at, err = tokenRepo.CreateAuthToken(ctx, user, at.AuthAccountId)
	require.NoError(t, err)
	encToken, err = authtoken.EncryptToken(context.Background(), kms, o.GetPublicId(), at.GetPublicId(), at.GetToken())
	require.NoError(t, err)
	tokValue = at.GetPublicId() + "_" + encToken

	// Add values for authn/authz checking
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokValue))
	requestInfo = authpb.RequestInfo{
		Path:   req.URL.Path,
		Method: req.Method,
	}
	requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = GetTokenFromRequest(context.TODO(), kms, req)
	verifierCtx = NewVerifierContext(ctx, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	// Create auth result from token
	res = Verify(verifierCtx, resourceType, WithScopeId(o.GetPublicId()))
	hash2, err := res.GrantsHash(ctx)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(hash1, hash2))

	// Change grants of the user
	newRole := iam.TestRole(t, conn, o.GetPublicId())
	_ = iam.TestRoleGrant(t, conn, newRole.GetPublicId(), "ids=*;type=*;actions=list-keys")
	_ = iam.TestUserRole(t, conn, newRole.GetPublicId(), user.GetPublicId())

	// Recreate auth result with new grants, should have a new hash
	res = Verify(verifierCtx, resourceType, WithScopeId(o.GetPublicId()))
	hash3, err := res.GrantsHash(ctx)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(hash1, hash3))
	assert.False(t, bytes.Equal(hash2, hash3))

	// Recreate auth result with no grants, should return a slice of empty bytes
	res.grants = nil
	hash4, err := res.GrantsHash(ctx)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(hash1, hash4))
	assert.False(t, bytes.Equal(hash2, hash4))
	assert.False(t, bytes.Equal(hash3, hash4))
	assert.True(t, bytes.Equal([]byte{0, 0, 0, 0, 0, 0, 0, 0}, hash4))
}
