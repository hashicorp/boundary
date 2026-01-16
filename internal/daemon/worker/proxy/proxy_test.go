// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestRegisterHandler(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	fn := func(context.Context, context.Context, DecryptFn, net.Conn, *ProxyDialer, string, *anypb.Any, RecordingManager, ...Option) (ProxyConnFn, error) {
		return nil, nil
	}
	oldHandler := handlers
	t.Cleanup(func() {
		handlers = oldHandler
	})
	handlers = new(sync.Map)

	err := RegisterHandler("protocol", fn)
	require.NoError(err)

	// Register function with same protocol
	err = RegisterHandler("protocol", fn)
	require.Error(err)
	assert.ErrorIs(err, ErrProtocolAlreadyRegistered)

	err = RegisterHandler("new-protocol", fn)
	require.NoError(err)
}

func TestAlwaysTcpGetHandler(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	fn := func(context.Context, context.Context, DecryptFn, net.Conn, *ProxyDialer, string, *anypb.Any, RecordingManager, ...Option) (ProxyConnFn, error) {
		return nil, nil
	}
	oldHandler := handlers
	t.Cleanup(func() {
		handlers = oldHandler
	})
	handlers = new(sync.Map)
	_, err := tcpOnly("wid", nil)
	assert.ErrorIs(err, ErrUnknownProtocol)

	require.NoError(RegisterHandler("tcp", fn))

	handler, err := tcpOnly("wid", nil)
	require.NoError(err)
	require.NotNil(handler)
}
