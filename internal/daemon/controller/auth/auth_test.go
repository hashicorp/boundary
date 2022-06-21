package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/tests/api"
	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthTokenAuthenticator(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	tokenRepo, err := authtoken.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
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

func TestVerify_AuditEvent(t *testing.T) {
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
	tokenRepo, err := authtoken.NewRepository(rw, rw, testKms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, testKms)
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
			wantUserId:        "u_anon",
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

			ctx := NewVerifierContext(context.Background(), iamRepoFn, tokenRepoFn, serversRepoFn, testKms, &requestInfo)

			_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
			_ = Verify(ctx, tt.opt...)
			got := api.CloudEventFromFile(t, eventConfig.AuditEvents.Name())

			if tt.wantAuthAuditData {
				auth, ok := got.Data.(map[string]interface{})["auth"].(map[string]interface{})
				require.True(ok)
				assert.Equal(encrypt.RedactedData, auth["email"])
				assert.Equal(encrypt.RedactedData, auth["name"])

				if tt.disableAuth {
					assert.Equal(true, auth["disabled_auth_entirely"])
				}
				if tt.wantUserId != "" {
					userInfo, ok := auth["user_info"].(map[string]interface{})
					require.True(ok)
					assert.Equal(tt.wantUserId, userInfo["id"])
				}
			}
		})
	}
}
