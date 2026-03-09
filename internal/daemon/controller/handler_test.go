// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/protobuf/proto"
)

func TestAuthenticationHandler(t *testing.T) {
	c := NewTestController(t, &TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultPasswordAuthMethodId:  "ampw_1234567890",
		DefaultLoginName:             "admin",
		DefaultPassword:              "password123",
	})
	defer c.Shutdown()

	request := map[string]any{
		"attributes": map[string]any{
			"login_name": "admin",
			"password":   "password123",
		},
	}
	// No "type" defined means "token" type
	b, err := json.Marshal(request)
	require.NoError(t, err)

	resp, err := http.Post(fmt.Sprintf("%s/v1/auth-methods/ampw_1234567890:authenticate", c.ApiAddrs()[0]), "application/json", bytes.NewReader(b))

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Got response: %v", resp)

	b, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	body := make(map[string]any)
	require.NoError(t, json.Unmarshal(b, &body))

	require.Contains(t, body, "attributes")
	attrs := body["attributes"].(map[string]any)
	pubId, tok := attrs["id"].(string), attrs["token"].(string)
	assert.NotEmpty(t, pubId)
	assert.NotEmpty(t, tok)
	assert.Truef(t, strings.HasPrefix(tok, pubId), "Token: %q, Id: %q", tok, pubId)

	// Set the token type to cookie and make sure the body does not contain the token anymore.
	request["type"] = "cookie"
	b, err = json.Marshal(request)
	require.NoError(t, err)
	resp, err = http.Post(fmt.Sprintf("%s/v1/auth-methods/ampw_1234567890:authenticate", c.ApiAddrs()[0]), "application/json", bytes.NewReader(b))

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Got response: %v", resp)

	b, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	body = make(map[string]any)
	require.NoError(t, json.Unmarshal(b, &body))

	attrs = body["attributes"].(map[string]any)

	require.Contains(t, attrs, "id")
	require.Contains(t, attrs, "auth_method_id")
	require.Contains(t, attrs, "user_id")
	require.NotContains(t, attrs, "token")

	cookies := make(map[string]*http.Cookie)
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c
	}
	require.Contains(t, cookies, handlers.HttpOnlyCookieName)
	require.Contains(t, cookies, handlers.JsVisibleCookieName)
	assert.NotEmpty(t, cookies[handlers.HttpOnlyCookieName].Value)
	assert.NotEmpty(t, cookies[handlers.JsVisibleCookieName].Value)
	assert.True(t, cookies[handlers.HttpOnlyCookieName].HttpOnly)
	assert.False(t, cookies[handlers.JsVisibleCookieName].HttpOnly)
	assert.Equal(t, cookies[handlers.HttpOnlyCookieName].Path, "/")
	assert.Equal(t, cookies[handlers.JsVisibleCookieName].Path, "/")
	tok = cookies[handlers.JsVisibleCookieName].Value

	pubId = attrs["id"].(string)
	assert.NotEmpty(t, pubId)
	assert.Truef(t, strings.HasPrefix(tok, pubId), "Token: %q, Id: %q", tok, pubId)
}

func TestHandleImplementedPaths(t *testing.T) {
	c := NewTestController(t, &TestControllerOpts{
		DisableAuthorizationFailures: true,
	})
	defer c.Shutdown()

	for verb, paths := range map[string][]string{
		"GET": {
			"v1/accounts",
			"v1/accounts/someid",
			"v1/aliases",
			"v1/aliases/someid",
			"v1/auth-methods",
			"v1/auth-methods/someid",
			"v1/auth-methods/someid:authenticate:callback",
			"v1/auth-tokens",
			"v1/auth-tokens/someid",
			"v1/credential-stores",
			"v1/credential-stores/someid",
			"v1/groups",
			"v1/groups/someid",
			"v1/host-catalogs",
			"v1/host-catalogs/someid",
			"v1/host-sets",
			"v1/host-sets/someid",
			"v1/hosts",
			"v1/hosts/someid",
			"v1/roles",
			"v1/roles/someid",
			"400_v1/sc\u200Bopes",
			"200_v1/scopes",
			"v1/scopes/someid",
			"v1/sessions",
			"v1/sessions/someid",
			"v1/storage-buckets",
			"v1/storage-buckets/someid",
			"v1/targets",
			"v1/targets/some_id",
			"v1/users",
			"v1/users/someid",
			"v1/billing:monthly-active-users",
		},
		"POST": {
			// Creation end points
			"v1/accounts",
			"v1/aliases",
			"v1/auth-methods",
			"v1/credential-stores",
			"v1/groups",
			"v1/host-catalogs",
			"v1/host-sets",
			"v1/hosts",
			"v1/roles",
			"v1/scopes",
			"v1/storage-buckets",
			"v1/targets",
			"v1/users",

			// custom methods
			"v1/accounts/someid:set-password",
			"v1/accounts/someid:change-password",
			"v1/auth-methods/someid:authenticate",
			"v1/groups/someid:add-members",
			"v1/groups/someid:set-members",
			"v1/groups/someid:remove-members",
			"v1/host-sets/someid:add-hosts",
			"v1/host-sets/someid:remove-hosts",
			"v1/host-sets/someid:set-hosts",
			"v1/roles/someid:add-grants",
			"v1/roles/someid:set-grants",
			"v1/roles/someid:remove-grants",
			"v1/roles/someid:add-principals",
			"v1/roles/someid:set-principals",
			"v1/roles/someid:remove-principals",
			"v1/sessions/someid:cancel",
			"v1/targets/some_id:authorize-session",
			"v1/targets/some_id:add-host-sources",
			"v1/targets/some_id:set-host-sources",
			"v1/targets/some_id:remove-host-sources",
			"v1/targets/some_id:add-credential-sources",
			"v1/targets/some_id:set-credential-sources",
			"v1/targets/some_id:remove-credential-sources",
			"v1/users/someid:add-accounts",
			"v1/users/someid:set-accounts",
			"v1/users/someid:remove-accounts",
		},
		"DELETE": {
			"v1/accounts/someid",
			"v1/aliases/someid",
			"v1/auth-methods/someid",
			"v1/auth-tokens/someid",
			"v1/credential-stores/someid",
			"v1/groups/someid",
			"v1/host-catalogs/someid",
			"v1/host-sets/someid",
			"v1/hosts/someid",
			"v1/roles/someid",
			"v1/scopes/someid",
			"v1/storage-buckets/someid",
			"v1/targets/some_id",
			"v1/users/someid",
		},
		"PATCH": {
			"v1/accounts/someid",
			"v1/aliases/someid",
			"v1/auth-methods/someid",
			"v1/credential-stores/someid",
			"v1/groups/someid",
			"v1/host-catalogs/someid",
			"v1/host-sets/someid",
			"v1/hosts/someid",
			"v1/roles/someid",
			"v1/scopes/someid",
			"v1/storage-buckets/someid",
			"v1/targets/some_id",
			"v1/users/someid",
		},
	} {
		for _, p := range paths {
			t.Run(fmt.Sprintf("%s/%s", verb, p), func(t *testing.T) {
				var expCode int
				if !strings.HasPrefix(p, "v1/") {
					sp := strings.Split(p, "_")
					require.Len(t, sp, 2)
					switch sp[0] {
					case "400":
						expCode = http.StatusBadRequest
					case "200":
						expCode = http.StatusOK
					}
					p = sp[1]
				}

				url := fmt.Sprintf("%s/%s", c.ApiAddrs()[0], p)
				req, err := http.NewRequest(verb, url, nil)
				require.NoError(t, err)
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				if expCode != 0 {
					assert.Equal(t, expCode, resp.StatusCode)
				}
				assert.NotEqualf(t, resp.StatusCode, http.StatusNotFound, "Got response %v, wanted not 404", resp.StatusCode)
			})
		}
	}
}

func TestCallbackInterceptor(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		// Ignore errors as a normal shutdown will also close the listener when
		// the server Shutdown is called. This is just in case.
		_ = listener.Close()
	}()

	noopHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		var buf bytes.Buffer
		read, err := buf.ReadFrom(r.Body)
		require.NoError(t, err)
		written, err := w.Write(buf.Bytes())
		require.NoError(t, err)
		require.EqualValues(t, read, written)
	})

	server := &http.Server{
		Handler: wrapHandlerWithCallbackInterceptor(noopHandler, nil),
	}

	// Use error channel so that we can use test assertions on the returned error.
	// It is illegal to call `t.FailNow()` from a goroutine.
	// https://pkg.go.dev/testing#T.FailNow
	errChan := make(chan error)
	go func() {
		errChan <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		if err := <-errChan; err != http.ErrServerClosed {
			require.NoError(t, err)
		}
	})

	testCases := []struct {
		name     string
		path     string
		args     url.Values
		wantJson *cmdAttrs
	}{
		{
			name: "not callback, no args",
			path: "v1/auth-methods/ampw_1234567890:read",
		},
		{
			name: "not callback, with args",
			path: "v1/auth-methods/ampw_1234567890:read",
			args: url.Values{
				"state": []string{"fooBar"},
				"token": []string{"barFoo"},
			},
		},
		{
			name:     "callback, no args",
			path:     "v1/auth-methods/ampw_1234567890:authenticate:callback",
			wantJson: &cmdAttrs{Command: "callback"},
		},
		{
			name: "callback, invalid pattern",
			path: "v1/auth-methods/ampw_1234567890:read:callback",
		},
		{
			name: "callback, with args",
			path: "v1/auth-methods/ampw_1234567890:authenticate:callback",
			args: url.Values{
				"state": []string{"fooBar"},
				"token": []string{"barFoo"},
			},
			wantJson: &cmdAttrs{
				Command: "callback",
				Attributes: map[string]any{
					"state": "fooBar",
					"token": "barFoo",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			req, err := http.NewRequest(http.MethodGet,
				fmt.Sprintf("http://%s/%s", listener.Addr().String(), tc.path),
				nil)
			require.NoError(err)

			if tc.args != nil {
				req.URL.RawQuery = tc.args.Encode()
			}

			resp, err := http.DefaultClient.Do(req)
			require.NoError(err)
			require.EqualValues(http.StatusOK, resp.StatusCode)

			if tc.wantJson != nil {
				require.NotNil(resp.Body)
				defer resp.Body.Close()
				wantJsonJson, err := json.Marshal(tc.wantJson)
				require.NoError(err)
				var buf bytes.Buffer
				_, err = buf.ReadFrom(resp.Body)
				require.NoError(err)
				require.Equal(wantJsonJson, buf.Bytes())
			} else {
				require.Equal(http.NoBody, resp.Body)
			}
		})
	}

	require.NoError(t, server.Shutdown(context.Background()))
}

func TestStreamingResponse(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	t.Cleanup(func() {
		// Ignore errors as a normal shutdown will also close the listener when
		// the server Shutdown is called. This is just in case.
		_ = listener.Close()
	})
	mux := newGrpcGatewayMux()
	marshaler := &noDelimiterStreamingMarshaler{
		&runtime.HTTPBodyMarshaler{
			Marshaler: handlers.JSONMarshaler(),
		},
	}
	size := 500
	blob := make([]byte, size)
	_, err = io.ReadFull(rand.Reader, blob)
	require.NoError(t, err)
	var i int
	n := 5
	recv := func() (proto.Message, error) {
		t.Log("Sending chunk", i)
		if i < n {
			buf := make([]byte, size/n)
			copy(buf, blob[i*len(buf):])
			i++
			return &httpbody.HttpBody{
				ContentType: "application/octet-stream",
				Data:        buf,
			}, nil
		}
		return nil, io.EOF
	}

	mux.HandlePath("GET", "/", runtime.HandlerFunc(func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		ctx := r.Context()
		ctx = runtime.NewServerMetadataContext(ctx, runtime.ServerMetadata{})
		runtime.ForwardResponseStream(ctx, mux, marshaler, w, r, recv)
	}))

	server := &http.Server{
		Handler: mux,
	}
	go func() {
		if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			assert.NoError(t, err)
		}
	}()
	t.Cleanup(func() {
		require.NoError(t, server.Shutdown(context.Background()))
	})
	resp, err := http.Get("http://" + listener.Addr().String())
	require.NoError(t, err)
	read, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.True(t, string(read) == string(blob), "Got: %q", string(read))
	require.Equal(t, i, n)
}

func TestGetActions(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		expected []string
	}{
		{
			name:     "No actions",
			url:      "/v1/auth-methods/amoidc_1234567890",
			expected: []string{},
		},
		{
			name:     "1 Action",
			url:      "/v1/auth-methods/amoidc_1234567890:authenticate",
			expected: []string{"authenticate"},
		},
		{
			name:     "Multiple Actions",
			url:      "https://hello.com/v1/auth-methods/amoidc_1234567890:authenticate:callback",
			expected: []string{"authenticate", "callback"},
		},
		{
			name:     "1 Action with query params",
			url:      "https://hello.com/v1/auth-methods/amoidc_1234567890:authenticate?state=foo&token=bar",
			expected: []string{"authenticate"},
		},
		{
			name:     "Multiple Actions with query params",
			url:      "https://hello.com/v1/auth-methods/amoidc_1234567890:authenticate:callback?state=foo&token=bar",
			expected: []string{"authenticate", "callback"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			actions := getActions(tc.url)
			fmt.Println("actions", len(actions))
			require.Equal(tc.expected, actions)
		})
	}
}
