// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProxyDialer(t *testing.T) {
	d, err := NewProxyDialer(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, d)

	d, err = NewProxyDialer(context.Background(), func(...Option) (net.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	})
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestProxyDialer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		_, _ = l.Accept()
	}()
	defer l.Close()
	ctx := context.Background()

	t.Run("Dial error", func(t *testing.T) {
		expectedErr := errors.New("test error")
		d, err := NewProxyDialer(ctx, func(...Option) (net.Conn, error) {
			return nil, expectedErr
		})
		require.NoError(t, err)
		assert.Nil(t, d.LastConnectionAddr())
		badC, err := d.Dial(ctx)
		require.Error(t, err)
		require.Nil(t, badC)
		assert.Nil(t, d.LastConnectionAddr())
	})

	t.Run("Successful Dial", func(t *testing.T) {
		d, err := NewProxyDialer(ctx, func(...Option) (net.Conn, error) {
			return net.Dial("tcp", l.Addr().String())
		})
		require.NoError(t, err)
		assert.Nil(t, d.LastConnectionAddr())
		c, err := d.Dial(ctx)
		require.NoError(t, err)
		require.NotNil(t, c)

		tcpAddr := l.Addr().(*net.TCPAddr)
		assert.Equal(t, tcpAddr.IP.String(), d.LastConnectionAddr().Ip())
		assert.EqualValues(t, tcpAddr.Port, d.LastConnectionAddr().Port())
	})
}
