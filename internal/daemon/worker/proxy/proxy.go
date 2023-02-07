// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"errors"
	"net"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

var (
	TcpHandlerName = "tcp"

	// handlers is the map of registered handlers
	handlers sync.Map

	// ErrUnknownProtocol specifies the provided protocol has no registered handler
	ErrUnknownProtocol = errors.New("proxy: handler not found for protocol")

	// ErrProtocolAlreadyRegistered specifies the provided protocol has already been registered
	ErrProtocolAlreadyRegistered = errors.New("proxy: protocol already registered")

	// GetHandler returns the handler registered for the provided worker and
	// protocolContext. If a protocol cannot be determined or the protocol is
	// not registered nil, ErrUnknownProtocol is returned.
	GetHandler = tcpOnly
)

// DecryptFn decrypts the provided bytes into a proto.Message
type DecryptFn func(ctx context.Context, from []byte, to proto.Message) error

// ProxyConnFn is called after the call to ConnectConnection on the cluster.
// ProxyConnFn blocks until the specific request that is being proxied is finished
type ProxyConnFn func(ctx context.Context)

// Handler is the type that all proxies need to implement to be called by the worker
// when a new client connection is created.  If there is an error ProxyConnFn must
// be nil. If there is no error ProxyConnFn must be set.  When Handler has
// returned, it is expected that the initial connection to the endpoint has been
// established.
type Handler func(context.Context, DecryptFn, net.Conn, *ProxyDialer, string, *anypb.Any) (ProxyConnFn, error)

func RegisterHandler(protocol string, handler Handler) error {
	_, loaded := handlers.LoadOrStore(protocol, handler)
	if loaded {
		return ErrProtocolAlreadyRegistered
	}
	return nil
}

// tcpOnly returns only the TCP protocol.
func tcpOnly(string, proto.Message) (Handler, error) {
	handler, ok := handlers.Load(TcpHandlerName)
	if !ok {
		return nil, ErrUnknownProtocol
	}
	return handler.(Handler), nil
}
