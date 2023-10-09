// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/ratelimit"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-rate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	cases := []struct {
		name          string
		limiter       *rate.Limiter
		req           func(uri string) *http.Request
		expectCode    int
		expectHeaders http.Header
	}{
		{
			"AllowedList",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusOK,
			http.Header{},
		},
		{
			"AllowedCreate",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.Create.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusOK,
			http.Header{},
		},
		{
			"AllowedRead",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.Read.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusOK,
			http.Header{},
		},
		{
			"AllowedUpdate",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.Update.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusOK,
			http.Header{},
		},
		{
			"AllowedDelete",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.Delete.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusOK,
			http.Header{},
		},
		{
			"AllowedAuthorizeSession",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.AuthorizeSession.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
						MaxRequests: 10,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodDelete, uri+"/v1/targets/ttcp_123456789:authorize-session", nil)
				require.NoError(t, err)
				return r
			},
			http.StatusOK,
			http.Header{},
		},
		{
			"Limited",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 10)
				require.NoError(t, err)
				_, q, err := r.Allow("target", "list")
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
			http.StatusTooManyRequests,
			http.Header{
				"Retry-After": []string{"60"},
			},
		},
		{
			"LimiterFull",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
						MaxRequests: 2,
						Period:      time.Minute,
					},
					{
						Resource:    resource.Target.String(),
						Action:      action.Read.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
						MaxRequests: 2,
						Period:      time.Minute,
					},
				}, 1)
				require.NoError(t, err)
				// use up all of the capacity for the limiter
				_, _, err = r.Allow("target", "read")
				require.NoError(t, err)
				return r
			}(),
			func(uri string) *http.Request {
				r, err := http.NewRequest(http.MethodGet, uri+"/v1/targets", nil)
				require.NoError(t, err)
				return r
			},
			http.StatusServiceUnavailable,
			http.Header{
				"Retry-After": []string{"1"},
			},
		},
		{
			"MissingLimit",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusInternalServerError,
			http.Header{},
		},
		{
			"UnknownResource",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusNotFound,
			http.Header{},
		},
		{
			"UnknownAction",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusBadRequest,
			http.Header{},
		},
		{
			"UnknownActionInvalidIdHttpMethod",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusMethodNotAllowed,
			http.Header{},
		},
		{
			"UnknownActionInvalidHttpMethod",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusMethodNotAllowed,
			http.Header{},
		},
		{
			"UnsupportedAction",
			func() *rate.Limiter {
				r, err := rate.NewLimiter([]*rate.Limit{
					{
						Resource:    resource.Target.String(),
						Action:      action.List.String(),
						Per:         rate.LimitPerTotal,
						Unlimited:   false,
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
			http.StatusMethodNotAllowed,
			http.Header{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(ratelimit.Handler(tc.limiter, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				return
			})))
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
