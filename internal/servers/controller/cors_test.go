package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/go-retryablehttp"
)

const corsTestConfig = `
disable_mlock = true

telemetry {
	prometheus_retention_time = "24h"
	disable_hostname = true
}

kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "09iqFxRJNYsl/b8CQxjnGw=="
	key_id = "global_root"
}

kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "09iqFxRJNYsl/b8CQxjnGw=="
	key_id = "global_worker-auth"
}

listener "tcp" {
	purpose = "cluster"
}

listener "tcp" {
	purpose = "api"
	tls_disable = true
	cors_enabled = false
}

listener "tcp" {
	purpose = "api"
	tls_disable = true
	cors_enabled = true
	cors_allowed_origins = []
}

listener "tcp" {
	purpose = "api"
	tls_disable = true
	cors_enabled = true
	cors_allowed_origins = ["foobar.com", "barfoo.com"]
}

listener "tcp" {
	purpose = "api"
	tls_disable = true
	cors_enabled = true
	cors_allowed_origins = ["*"]
	cors_allowed_headers = ["x-foobar"]
}
`

func TestHandler_CORS(t *testing.T) {
	cfg, err := config.Parse(corsTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	tc := NewTestController(t, &TestControllerOpts{
		Config:                       cfg,
		DisableAuthorizationFailures: true,
	})
	defer tc.Shutdown()

	repo := tc.IamRepo()
	require.NoError(t, err)
	org := iam.TestOrg(t, repo)

	encToken, err := authtoken.EncryptToken(context.Background(), tc.c.kms, org.GetPublicId(), "fo_o", "bar")
	require.NoError(t, err)
	token := "fo_o_" + encToken

	cases := []struct {
		name           string
		method         string
		origin         string
		code           int
		acrmHeader     string
		allowedHeader  string
		listenerNum    int
		provideScopeId bool
	}{
		{
			name:        "disabled no origin",
			method:      http.MethodPost,
			code:        http.StatusOK,
			listenerNum: 1,
		},
		{
			name:        "disabled with origin",
			method:      http.MethodPost,
			origin:      "foobar.com",
			code:        http.StatusOK,
			listenerNum: 1,
		},
		{
			name:        "enabled with no allowed origins and no origin defined",
			method:      http.MethodPost,
			code:        http.StatusOK,
			listenerNum: 2,
		},
		{
			name:        "enabled with no allowed origins and origin defined",
			method:      http.MethodPost,
			origin:      "foobar.com",
			code:        http.StatusForbidden,
			listenerNum: 2,
		},
		{
			name:        "enabled with allowed origins and no origin defined",
			method:      http.MethodPost,
			code:        http.StatusOK,
			listenerNum: 3,
		},
		{
			name:        "enabled with allowed origins and bad origin defined",
			method:      http.MethodPost,
			origin:      "flubber.com",
			code:        http.StatusForbidden,
			listenerNum: 3,
		},
		{
			name:        "enabled with allowed origins and good origin defined",
			method:      http.MethodPost,
			origin:      "barfoo.com",
			code:        http.StatusOK,
			listenerNum: 3,
		},
		{
			name:        "enabled with allowed origins and desktop origin",
			method:      http.MethodPost,
			origin:      "serve://boundary",
			code:        http.StatusOK,
			listenerNum: 3,
		},
		{
			name:        "enabled with wildcard origins and no origin defined",
			method:      http.MethodPost,
			code:        http.StatusOK,
			listenerNum: 4,
		},
		{
			name:        "enabled with wildcard origins and origin defined",
			method:      http.MethodPost,
			origin:      "flubber.com",
			code:        http.StatusOK,
			listenerNum: 4,
		},
		{
			name:           "enabled with wildcard origins and no origin defined, scope id checking",
			method:         http.MethodGet,
			code:           http.StatusOK,
			listenerNum:    4,
			provideScopeId: true,
		},
		{
			name:           "enabled with wildcard origins and origin defined, scope id checking",
			method:         http.MethodPost,
			origin:         "flubber.com",
			code:           http.StatusOK,
			listenerNum:    4,
			provideScopeId: true,
		},
		{
			name:        "wildcard origins with method list and good method",
			method:      http.MethodOptions,
			origin:      "flubber.com",
			code:        http.StatusNoContent,
			acrmHeader:  "DELETE",
			listenerNum: 4,
		},
		{
			name:          "wildcard origins with method list and bad method",
			method:        http.MethodOptions,
			origin:        "flubber.com",
			code:          http.StatusMethodNotAllowed,
			acrmHeader:    "BADSTUFF",
			allowedHeader: "X-Foobar",
			listenerNum:   4,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Create a client with the right address
			client := tc.Client()
			err := client.SetAddr(tc.ApiAddrs()[c.listenerNum-1])
			require.NoError(t, err)

			client.SetToken(token)

			// Create the request
			var req *retryablehttp.Request

			// This tests out scope_id handling from body or query
			var body interface{}
			scopeId := "global"
			if c.provideScopeId {
				scopeId = org.GetPublicId()
			}

			if c.method == http.MethodPost {
				body = map[string]interface{}{
					"scope_id": scopeId,
				}
			}

			req, err = client.NewRequest(tc.Context(), c.method, "scopes", body)
			require.NoError(t, err)

			if c.method == http.MethodGet {
				q := url.Values{}
				q.Add("scope_id", scopeId)
				req.URL.RawQuery = q.Encode()
			}

			// Append headers
			if c.origin != "" {
				req.Header.Add("Origin", c.origin)
			}
			if c.acrmHeader != "" {
				req.Header.Add("Access-Control-Request-Method", c.acrmHeader)
			}

			// Run the request, do basic checks
			resp, err := client.Do(req)
			require.NoError(t, err)
			assert.Equal(t, c.code, resp.HttpResponse().StatusCode)

			// If options and we expect it to be successful, run some checks
			if req.Method == http.MethodOptions && c.code == http.StatusNoContent {
				assert.Equal(t, fmt.Sprintf("%s, %s, %s, %s, %s", http.MethodDelete, http.MethodGet, http.MethodOptions, http.MethodPost, http.MethodPatch), resp.HttpResponse().Header.Get("Access-Control-Allow-Methods"))
				assert.Equal(t, fmt.Sprintf("%s, %s, %s, %s", "Content-Type", "X-Requested-With", "Authorization", "X-Foobar"), resp.HttpResponse().Header.Get("Access-Control-Allow-Headers"))
				assert.Equal(t, "300", resp.HttpResponse().Header.Get("Access-Control-Max-Age"))
			}

			// If origin was set and we expect it to be successful, run some more checks
			if c.origin != "" && c.code == http.StatusOK && c.listenerNum > 1 {
				assert.Equal(t, c.origin, resp.HttpResponse().Header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "Origin", resp.HttpResponse().Header.Get("Vary"))
			}
		})
	}
}
