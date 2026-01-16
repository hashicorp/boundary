// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ratelimit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-rate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name          string
		limiter       *rate.Limiter
		req           func(uri string) *http.Request
		ip            string
		authtoken     string
		expectCode    int
		expectHeaders http.Header
	}{
		{
			"AllowedList",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 10,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodGet, uri+"/v1/targets", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusOK,
			http.Header{
				"RateLimit-Policy": []string{`10;w=60;comment="total", 10;w=60;comment="ip-address", 10;w=60;comment="auth-token"`},
				"RateLimit":        []string{`limit=10, remaining=9, reset=60`},
			},
		},
		{
			"AllowedCreate",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Create.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Create.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Create.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 10,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodPost, uri+"/v1/targets", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusOK,
			http.Header{
				"RateLimit-Policy": []string{`10;w=60;comment="total", 10;w=60;comment="ip-address", 10;w=60;comment="auth-token"`},
				"RateLimit":        []string{`limit=10, remaining=9, reset=60`},
			},
		},
		{
			"AllowedRead",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Read.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Read.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Read.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 10,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodGet, uri+"/v1/targets/ttcp_123456789", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusOK,
			http.Header{
				"RateLimit-Policy": []string{`10;w=60;comment="total", 10;w=60;comment="ip-address", 10;w=60;comment="auth-token"`},
				"RateLimit":        []string{`limit=10, remaining=9, reset=60`},
			},
		},
		{
			"AllowedUpdate",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Update.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Update.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Update.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 10,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodPatch, uri+"/v1/targets/ttcp_123456789", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusOK,
			http.Header{
				"RateLimit-Policy": []string{`10;w=60;comment="total", 10;w=60;comment="ip-address", 10;w=60;comment="auth-token"`},
				"RateLimit":        []string{`limit=10, remaining=9, reset=60`},
			},
		},
		{
			"AllowedDelete",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Delete.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Delete.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Delete.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 10,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodDelete, uri+"/v1/targets/ttcp_123456789", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusOK,
			http.Header{
				"RateLimit-Policy": []string{`10;w=60;comment="total", 10;w=60;comment="ip-address", 10;w=60;comment="auth-token"`},
				"RateLimit":        []string{`limit=10, remaining=9, reset=60`},
			},
		},
		{
			"AllowedAuthorizeSession",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.AuthorizeSession.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.AuthorizeSession.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.AuthorizeSession.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 10,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodPut, uri+"/v1/targets/ttcp_123456789:authorize-session", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusOK,
			http.Header{
				"RateLimit-Policy": []string{`10;w=60;comment="total", 10;w=60;comment="ip-address", 10;w=60;comment="auth-token"`},
				"RateLimit":        []string{`limit=10, remaining=9, reset=60`},
			},
		},
		{
			"AllowedAuthorizeSessionTargetNameSlash",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.AuthorizeSession.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.AuthorizeSession.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 10,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.AuthorizeSession.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 10,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodPut, uri+`/v1/targets/E2E/Test-Target-With\Name:authorize-session`, nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusOK,
			http.Header{
				"RateLimit-Policy": []string{`10;w=60;comment="total", 10;w=60;comment="ip-address", 10;w=60;comment="auth-token"`},
				"RateLimit":        []string{`limit=10, remaining=9, reset=60`},
			},
		},
		{
			"Limited",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				_, q, err := r.Allow("target", "list", "", "")
				require.NoError(t, err)

				// consume all of the quota
				remaining := int(q.Remaining())
				for i := 0; i < remaining; i++ {
					q.Consume()
				}
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodGet, uri+"/v1/targets", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusTooManyRequests,
			http.Header{
				"Retry-After":      []string{"60"},
				"RateLimit-Policy": []string{`2;w=60;comment="total", 2;w=60;comment="ip-address", 2;w=60;comment="auth-token"`},
				"RateLimit":        []string{`limit=2, remaining=0, reset=60`},
			},
		},
		{
			"LimiterFull",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Read.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Read.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.Read.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 3)
				require.NoError(t, err)
				// use up all of the capacity for the limiter
				_, _, err = r.Allow("target", "read", "", "")
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodGet, uri+"/v1/targets", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusServiceUnavailable,
			http.Header{
				"Retry-After": []string{"1"},
			},
		},
		{
			"MissingLimit",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodPost, uri+"/v1/targets", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusInternalServerError,
			http.Header{},
		},
		{
			"UnknownResource",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodPost, uri+"/v1/foo", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusNotFound,
			http.Header{},
		},
		{
			"UnknownAction",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodPut, uri+"/v1/target/ttcp_123456789:foo", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusBadRequest,
			http.Header{},
		},
		{
			"UnknownActionInvalidIdHttpMethod",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodPost, uri+"/v1/target/ttcp_123456789", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusMethodNotAllowed,
			http.Header{},
		},
		{
			"UnknownActionInvalidHttpMethod",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodDelete, uri+"/v1/target", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusMethodNotAllowed,
			http.Header{},
		},
		{
			"UnsupportedAction",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]rate.Limit{
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerIPAddress,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					&rate.Limited{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerAuthToken,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodPut, uri+"/v1/host/hst_123456789:authorize-session", nil)
				require.NoError(t, err)
				return r
			},
			"::1",
			"authtoken",
			http.StatusMethodNotAllowed,
			http.Header{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(
				func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
						ctx := req.Context()
						id, err := event.NewId(event.IdPrefix)
						require.NoError(t, err)
						ctx, err = event.NewRequestInfoContext(ctx, &event.RequestInfo{
							Id:       id,
							EventId:  common.GeneratedTraceId(ctx),
							ClientIp: tc.ip,
						})
						require.NoError(t, err)
						ctx = context.WithValue(ctx, globals.ContextAuthTokenPublicIdKey, tc.authtoken)

						req = req.Clone(ctx)

						next.ServeHTTP(rw, req)
					})
				}(ratelimit.Handler(ctx, func() ratelimit.Limiter { return tc.limiter }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					return
				}))),
			)
			req := tc.req(server.URL)
			client := &http.Client{}
			res, err := client.Do(req)
			require.NoError(t, err)
			assert.Equal(t, tc.expectCode, res.StatusCode)
			for key, value := range tc.expectHeaders {
				assert.Equal(t, value[0], res.Header.Get(key))
			}
		})
	}
}

func TestHandlerErrors(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		ctxFn      func(context.Context) context.Context
		expectCode int
	}{
		{
			"NoRequestInfo",
			func(ctx context.Context) context.Context {
				ctx = context.WithValue(ctx, globals.ContextAuthTokenPublicIdKey, "auth-token")
				return ctx
			},
			http.StatusInternalServerError,
		},
		{
			"ClientIpEmptyString",
			func(ctx context.Context) context.Context {
				id, err := event.NewId(event.IdPrefix)
				require.NoError(t, err)
				ctx, err = event.NewRequestInfoContext(ctx, &event.RequestInfo{
					Id:       id,
					EventId:  common.GeneratedTraceId(ctx),
					ClientIp: "",
				})
				require.NoError(t, err)
				ctx = context.WithValue(ctx, globals.ContextAuthTokenPublicIdKey, "auth-token")
				return ctx
			},
			http.StatusInternalServerError,
		},
		{
			"NoAuthToken",
			func(ctx context.Context) context.Context {
				id, err := event.NewId(event.IdPrefix)
				require.NoError(t, err)
				ctx, err = event.NewRequestInfoContext(ctx, &event.RequestInfo{
					Id:       id,
					EventId:  common.GeneratedTraceId(ctx),
					ClientIp: "::1",
				})
				require.NoError(t, err)
				return ctx
			},
			http.StatusInternalServerError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := rate.NewLimiter([]rate.Limit{
				&rate.Limited{
					Resource:    resource.Target.String(),
					Action:      action.List.String(),
					Per:         rate.LimitPerTotal,
					MaxRequests: 10,
					Period:      time.Minute,
				},
				&rate.Limited{
					Resource:    resource.Target.String(),
					Action:      action.List.String(),
					Per:         rate.LimitPerIPAddress,
					MaxRequests: 10,
					Period:      time.Minute,
				},
				&rate.Limited{
					Resource:    resource.Target.String(),
					Action:      action.List.String(),
					Per:         rate.LimitPerAuthToken,
					MaxRequests: 10,
					Period:      time.Minute,
				},
			}, 10)
			require.NoError(t, err)
			server := httptest.NewServer(
				func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
						ctx := tc.ctxFn(req.Context())
						req = req.Clone(ctx)

						next.ServeHTTP(rw, req)
					})
				}(ratelimit.Handler(ctx, func() ratelimit.Limiter { return r }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					return
				}))),
			)
			req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/targets", nil)
			require.NoError(t, err)
			client := &http.Client{}
			res, err := client.Do(req)
			require.NoError(t, err)
			assert.Equal(t, tc.expectCode, res.StatusCode)
		})
	}
}
