// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-sockaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ClientIpFromRequest(t *testing.T) {
	// Cannot run in parallels since it relies on the pkg var common.privateNets
	testCtx := context.Background()
	testReq := func(remote, realIp string, forwardedFor ...string) *http.Request {
		h := http.Header{}
		h.Set("X-Real-IP", realIp)
		for _, address := range forwardedFor {
			h.Set("X-Forwarded-For", address)
		}
		return &http.Request{
			RemoteAddr: remote,
			Header:     h,
		}
	}

	pub1 := "147.12.56.100"
	pub2 := "119.14.55.11"
	localAddr := "127.0.0.1:101"
	goodAddr, err := sockaddr.NewIPAddr(localAddr)
	require.NoError(t, err)

	tests := []struct {
		name            string
		request         *http.Request
		listenerCfg     *listenerutil.ListenerConfig
		wantAddr        string
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "missing-request",
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing http request",
		},
		{
			name:            "missing-listener-config",
			request:         testReq(pub1, ""),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing listener config",
		},
		{
			name:    "no-header-remote-addr",
			request: testReq(pub1, ""),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantAddr: pub1,
		},
		{
			name:    "no-header-remote-addr-with-port",
			request: testReq(pub1+":49152", ""),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantAddr: pub1,
		},
		{
			name:    "one-x-forwarded",
			request: testReq(localAddr, "", pub1),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantAddr: pub1,
		},
		{
			name:    "no-trusted-x-forwarded-with-remote-addr",
			request: testReq(localAddr, "", ""),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantAddr: "127.0.0.1",
		},
		{
			name:    "no-trusted-x-forwarded-with-bad-remote-addr",
			request: testReq(localAddr+":22", "", ""),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "too many colons in address",
		},
		{
			name:    "many-x-forwarded",
			request: testReq(localAddr, "", localAddr, pub1, pub2),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantAddr: pub2,
		},
		{
			name:    "real-ip", // will fallback to remote addr, since real-ip isn't enabled for boundary
			request: testReq(localAddr, pub1),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantAddr: "127.0.0.1",
		},
		{
			name:    "local-forwaredfor-no-real-ip-use-remote-addr",
			request: testReq(pub1, "", localAddr),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantAddr: pub1,
		},
		{
			name:    "trusted-x-forwarded-for-success",
			request: testReq(localAddr, "", pub1),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = true
				listenerConfig.XForwardedForRejectNotAuthorized = true
				return listenerConfig
			}(),
			wantAddr: pub1,
		},
		{
			name:    "trusted-x-forwarded-for-failed",
			request: testReq("", "", localAddr),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = true
				listenerConfig.XForwardedForRejectNotAuthorized = true
				return listenerConfig
			}(),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "failed to determine trusted X-Forwarded-For",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotAddr, err := ClientIpFromRequest(testCtx, tt.listenerCfg, tt.request)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch.Code, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantAddr, gotAddr)
		})
	}
}

func cfgListener(addr sockaddr.IPAddr) *listenerutil.ListenerConfig {
	return &listenerutil.ListenerConfig{
		XForwardedForAuthorizedAddrs: []*sockaddr.SockAddrMarshaler{
			{
				SockAddr: addr,
			},
		},
	}
}
