// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("nil", func(t *testing.T) {
		opts, err := getOpts(nil)
		require.NoError(t, err)
		assert.NotNil(t, opts)
	})
	t.Run("with-listener", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts()
		require.NoError(t, err)
		assert.Nil(opts.WithListener)
		_, err = getOpts(WithListener(nil))
		require.Error(t, err)
		l := &net.TCPListener{}
		opts, err = getOpts(WithListener(l))
		require.NoError(t, err)
		assert.Equal(l, opts.WithListener)
	})
	t.Run("with-listen-addr-port", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts()
		require.NoError(t, err)
		assert.EqualValues(netip.MustParseAddrPort("127.0.0.1:0"), opts.WithListenAddrPort)
		_, err = getOpts(WithListenAddrPort(netip.AddrPort{}))
		require.Error(t, err)
		l := netip.AddrPortFrom(netip.IPv6LinkLocalAllNodes(), 22)
		opts, err = getOpts(WithListenAddrPort(l))
		require.NoError(t, err)
		assert.Equal(l, opts.WithListenAddrPort)
	})
	t.Run("with-connections-left-ch", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts()
		require.NoError(t, err)
		assert.Nil(opts.WithConnectionsLeftCh)
		_, err = getOpts(WithConnectionsLeftCh(nil))
		require.Error(t, err)
		l := make(chan int32)
		opts, err = getOpts(WithConnectionsLeftCh(l))
		require.NoError(t, err)
		assert.Equal(l, opts.WithConnectionsLeftCh)
	})
	t.Run("with-worker-host", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts()
		require.NoError(t, err)
		assert.Empty(opts.WithWorkerHost)
		opts, err = getOpts(WithWorkerHost("foo"))
		require.NoError(t, err)
		assert.Equal("foo", opts.WithWorkerHost)
	})
	t.Run("with-session-authorization-data", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts()
		require.NoError(t, err)
		assert.Nil(opts.WithSessionAuthorizationData)
		_, err = getOpts(WithSessionAuthorizationData(nil))
		require.Error(t, err)
		l := &targets.SessionAuthorizationData{}
		opts, err = getOpts(WithSessionAuthorizationData(l))
		require.NoError(t, err)
		assert.Equal(l, opts.WithSessionAuthorizationData)
	})
	t.Run("with-skip-session-teardown", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts()
		require.NoError(t, err)
		assert.Empty(opts.WithSkipSessionTeardown)
		opts, err = getOpts(WithSkipSessionTeardown(true))
		require.NoError(t, err)
		assert.True(opts.WithSkipSessionTeardown)
	})
	t.Run("withSessionTeardownTimeout", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts()
		require.NoError(t, err)
		assert.Empty(opts.withSessionTeardownTimeout)
		opts, err = getOpts(WithSessionTeardownTimeout(3 * time.Millisecond))
		require.NoError(t, err)
		assert.Equal(3*time.Millisecond, opts.withSessionTeardownTimeout)
	})
	t.Run("withSessionsClient", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts()
		require.NoError(t, err)
		assert.Nil(opts.withApiClient)
		client, err := api.NewClient(nil)
		require.NoError(t, err)
		opts, err = getOpts(WithApiClient(client))
		require.NoError(t, err)
		assert.Equal(client, opts.withApiClient)
	})
	t.Run("WithInactivityTimeout", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts()
		require.NoError(t, err)
		assert.Empty(opts.withInactivityTimeout)
		opts, err = getOpts(WithInactivityTimeout(3 * time.Millisecond))
		require.NoError(t, err)
		assert.Equal(3*time.Millisecond, opts.withInactivityTimeout)
	})
}
