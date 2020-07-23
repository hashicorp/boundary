package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/cmd/config"
)

const corsTestConfig = `
disable_mlock = true

telemetry {
        prometheus_retention_time = "24h"
        disable_hostname = true
}

kms "aead" {
        purpose = "controller"
        aead_type = "aes-gcm"
        key = "09iqFxRJNYsl/b8CQxjnGw=="
}

kms "aead" {
        purpose = "worker-auth"
        aead_type = "aes-gcm"
        key = "09iqFxRJNYsl/b8CQxjnGw=="
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
		DefaultOrgId:                 "o_1234567890",
		DisableAuthorizationFailures: true,
	})
	defer tc.Shutdown()

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
			client.SetScopeId("o_1234567890")
			client.SetToken("fo_o_bar")

			// Create the request
			var req *retryablehttp.Request

			// This tests out scope_id handling from body or query
			var body interface{}
			scopeId := "global"
			if c.provideScopeId {
				scopeId = "o_1234567890"
				if c.method == http.MethodPost {
					body = &scopes.Scope{}
				}
			}
			req, err = client.NewRequest(tc.Context(), c.method, "scopes", body)
			require.NoError(t, err)
			q := url.Values{}
			q.Add("scope_id", scopeId)
			req.URL.RawQuery = q.Encode()

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
