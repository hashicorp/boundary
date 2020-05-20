package controller

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

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
}
`

func TestHandler_CORS(t *testing.T) {
	cfg, err := config.Parse(corsTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	tc := NewTestController(t, &TestControllerOpts{
		Config:       cfg,
		DefaultOrgId: "o_1234567890",
	})
	defer tc.Shutdown()

	cases := []struct {
		name        string
		method      string
		origin      string
		code        int
		listenerNum int
	}{
		{
			"disabled no origin",
			http.MethodPost,
			"",
			http.StatusOK,
			1,
		},
		{
			"disabled with origin",
			http.MethodPost,
			"foobar.com",
			http.StatusOK,
			1,
		},
		{
			"enabled with no allowed origins and no origin defined",
			http.MethodPost,
			"",
			http.StatusOK,
			2,
		},
		{
			"enabled with no allowed origins and origin defined",
			http.MethodPost,
			"foobar.com",
			http.StatusForbidden,
			2,
		},
		{
			"enabled with allowed origins and no origin defined",
			http.MethodPost,
			"",
			http.StatusOK,
			3,
		},
		{
			"enabled with allowed origins and bad origin defined",
			http.MethodPost,
			"flubber.com",
			http.StatusForbidden,
			3,
		},
		{
			"enabled with allowed origins and good origin defined",
			http.MethodPost,
			"barfoo.com",
			http.StatusOK,
			3,
		},
		{
			"enabled with wildcard origins and no origin defined",
			http.MethodPost,
			"",
			http.StatusOK,
			4,
		},
		{
			"enabled with wildcard origins and origin defined",
			http.MethodPost,
			"flubber.com",
			http.StatusOK,
			4,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := tc.Client()
			client.SetAddr(tc.ApiAddrs()[c.listenerNum-1])
			req, err := client.NewRequest(tc.Context(), c.method, "orgs/o_1234567890/projects", nil)
			assert.NoError(t, err)
			if c.origin != "" {
				req.Header.Add("Origin", c.origin)
			}
			resp, err := client.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, c.code, resp.HttpResponse().StatusCode)
		})
	}

	/*

		req, err := http.NewRequest(http.MethodOptions, addr+"/v1/sys/seal-status", nil)
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		req.Header.Set("Origin", "BAD ORIGIN")

		// Requests from unacceptable origins will be rejected with a 403.
		client := cleanhttp.DefaultClient()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("Bad status:\nexpected: 403 Forbidden\nactual: %s", resp.Status)
		}

		//
		// Test preflight requests
		//

		// Set a valid origin
		req.Header.Set("Origin", addr)

		// Server should NOT accept arbitrary methods.
		req.Header.Set("Access-Control-Request-Method", "FOO")

		client = cleanhttp.DefaultClient()
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		// Fail if an arbitrary method is accepted.
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("Bad status:\nexpected: 405 Method Not Allowed\nactual: %s", resp.Status)
		}

		// Server SHOULD accept acceptable methods.
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)

		client = cleanhttp.DefaultClient()
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		//
		// Test that the CORS headers are applied correctly.
		//
		expHeaders := map[string]string{
			"Access-Control-Allow-Origin":  addr,
			"Access-Control-Allow-Headers": strings.Join(vault.StdAllowedHeaders, ","),
			"Access-Control-Max-Age":       "300",
			"Vary":                         "Origin",
		}

		for expHeader, expected := range expHeaders {
			actual := resp.Header.Get(expHeader)
			if actual == "" {
				t.Fatalf("bad:\nHeader: %#v was not on response.", expHeader)
			}

			if actual != expected {
				t.Fatalf("bad:\nExpected: %#v\nActual: %#v\n", expected, actual)
			}
		}
	*/
}
