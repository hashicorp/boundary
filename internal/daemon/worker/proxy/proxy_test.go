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

	fn := func(context.Context, net.Conn, *ProxyDialer, string, *anypb.Any) (ProxyConnFn, error) {
		return nil, nil
	}
	oldHandler := handlers
	t.Cleanup(func() {
		handlers = oldHandler
	})
	handlers = sync.Map{}

	err := RegisterHandler("protocol", fn)
	require.NoError(err)

	// Register function with same protocol
	err = RegisterHandler("protocol", fn)
	require.Error(err)
	assert.ErrorIs(err, ErrProtocolAlreadyRegistered)

	err = RegisterHandler("new-protocol", fn)
	require.NoError(err)
}

func TestGetHandler(t *testing.T) {
	assert, require := assert.New(t), require.New(t)

	fn := func(context.Context, net.Conn, *ProxyDialer, string, *anypb.Any) (ProxyConnFn, error) {
		return nil, nil
	}
	oldHandler := handlers
	t.Cleanup(func() {
		handlers = oldHandler
	})
	handlers = sync.Map{}

	err := RegisterHandler("fn", fn)
	require.NoError(err)

	gotFn, err := GetHandler("fake")
	require.Error(err)
	assert.ErrorIs(err, ErrUnknownProtocol)
	assert.Nil(gotFn)

	gotFn, err = GetHandler("fn")
	require.NoError(err)
	assert.NotNil(gotFn)
}
