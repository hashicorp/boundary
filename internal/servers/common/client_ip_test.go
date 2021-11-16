package common

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-sockaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPrivateAddr(t *testing.T) {
	// Cannot run in parallels since it relies on the pkg var common.privateNets
	testCtx := context.Background()
	require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
	tests := []struct {
		name            string
		addr            string
		nets            []*net.IPNet
		private         bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "missing-addr",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing address",
		},
		{
			name:            "missing-private-nets",
			addr:            "127.0.0.0",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing list of private networks",
		},
		{
			name: "bad-addr",
			addr: "&localhost",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "address is not valid",
		},
		{
			name: "127.0.0.0",
			addr: "127.0.0.0",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: true,
		},
		{
			name: "169.254.0.0",
			addr: "169.254.0.0",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: true,
		},
		{
			name: "192.168.0.0",
			addr: "192.168.0.0",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: true,
		},
		{
			name: "10.0.0.0",
			addr: "10.0.0.0",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: true,
		},
		{
			name: "fc00::",
			addr: "fc00::",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: true,
		},
		{
			name: "::1",
			addr: "::1",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: true,
		},
		{
			name: "172.16.0.0",
			addr: "172.16.0.0",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: true,
		},
		{
			name: "172.31.0.0",
			addr: "172.31.0.0",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: true,
		},
		{
			name: "172.15.0.0",
			addr: "172.15.0.0",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: false,
		},
		{
			name: "172.32.0.0",
			addr: "172.32.0.0",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: false,
		},
		{
			name: "147.12.56.100",
			addr: "147.12.56.100",
			nets: func() []*net.IPNet {
				require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
				return PrivateNetworks(testCtx)
			}(),
			private: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := isPrivateAddr(testCtx, tt.nets, tt.addr)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.False(got)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch.Code, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			if tt.private {
				assert.True(got)
			} else {
				assert.False(got)
			}
		})
	}
}

func Test_InitPrivateNetworks(t *testing.T) {
	// Cannot run in parallels since it relies on the pkg var common.privateNets
	testCtx := context.Background()
	tests := []struct {
		name            string
		blocks          []string
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-blocks",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing list of cidr blocks",
		},
		{
			name:            "missing-blocks",
			blocks:          []string{"bad-block"},
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "invalid cidr block",
		},
		{
			name:   "valid",
			blocks: PrivateCidrBlocks(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var tmp []*net.IPNet
			privateNets.Store(tmp)
			err := InitPrivateNetworks(testCtx, tt.blocks)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted %q and got %q", tt.wantErrMatch.Code, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}

func Test_PrivateNetworks(t *testing.T) {
	// Cannot run in parallels since it relies on the pkg var common.privateNets
	testCtx := context.Background()
	t.Run("nil", func(t *testing.T) {
		assert := assert.New(t)
		var tmp []*net.IPNet
		privateNets.Store(tmp)
		assert.Nil(PrivateNetworks(testCtx))
	})
	t.Run("initialized", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		var tmp []*net.IPNet
		privateNets.Store(tmp)
		require.NoError(InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
		assert.NotNil(PrivateNetworks(testCtx))
		assert.Len(PrivateNetworks(testCtx), len(PrivateCidrBlocks()))
	})
}

func Test_ClientIpFromRequest(t *testing.T) {
	// Cannot run in parallels since it relies on the pkg var common.privateNets
	testCtx := context.Background()
	require.NoError(t, InitPrivateNetworks(testCtx, PrivateCidrBlocks()))
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
	localAddr := "127.0.0.1"
	goodAddr, err := sockaddr.NewIPAddr(localAddr)
	require.NoError(t, err)

	tests := []struct {
		name            string
		request         *http.Request
		listenerCfg     *listenerutil.ListenerConfig
		privateNets     []*net.IPNet
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
			privateNets:     PrivateNetworks(testCtx),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing http request",
		},
		{
			name:    "missing-private-networks",
			request: testReq(pub1, ""),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing list of private networks",
		},
		{
			name:            "missing-listener-config",
			request:         testReq(pub1, ""),
			privateNets:     PrivateNetworks(testCtx),
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
			privateNets: PrivateNetworks(testCtx),
			wantAddr:    pub1,
		},
		{
			name:    "no-header-remote-addr-with-port",
			request: testReq(pub1+":49152", ""),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			privateNets: PrivateNetworks(testCtx),
			wantAddr:    pub1,
		},
		{
			name:    "one-x-forwarded",
			request: testReq("", "", pub1),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			privateNets: PrivateNetworks(testCtx),
			wantAddr:    pub1,
		},
		{
			name:    "many-x-forwared",
			request: testReq("", "", localAddr, pub1, pub2),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			privateNets: PrivateNetworks(testCtx),
			wantAddr:    pub2,
		},
		{
			name:    "real-ip",
			request: testReq("", pub1),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			privateNets: PrivateNetworks(testCtx),
			wantAddr:    pub1,
		},
		{
			name:    "local-forwaredfor-no-real-ip-use-remote-addr",
			request: testReq(pub1, "", localAddr),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = false
				return listenerConfig
			}(),
			privateNets: PrivateNetworks(testCtx),
			wantAddr:    pub1,
		},
		{
			name:    "trusted-x-forwarded-for-success",
			request: testReq(localAddr+":2", "", localAddr),
			listenerCfg: func() *listenerutil.ListenerConfig {
				listenerConfig := cfgListener(goodAddr)
				listenerConfig.XForwardedForRejectNotPresent = true
				listenerConfig.XForwardedForRejectNotAuthorized = true
				return listenerConfig
			}(),
			privateNets: PrivateNetworks(testCtx),
			wantAddr:    localAddr,
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
			privateNets:     PrivateNetworks(testCtx),
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "failed to determine trusted X-Forwarded-For",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotAddr, err := ClientIpFromRequest(testCtx, tt.privateNets, tt.listenerCfg, tt.request)
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
