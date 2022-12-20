package proxy

import (
	"context"
	"errors"
	"net"
	"sync"

	"google.golang.org/protobuf/types/known/anypb"
)

var (
	// handlers is the map of registered handlers
	handlers sync.Map

	// ErrUnknownProtocol specifies the provided protocol has no registered handler
	ErrUnknownProtocol = errors.New("proxy: handler not found for protocol")

	// ErrProtocolAlreadyRegistered specifies the provided protocol has already been registered
	ErrProtocolAlreadyRegistered = errors.New("proxy: protocol already registered")
)

// ProxyConnFn is called after the call to ConnectConnection on the cluster.
// ProxyConnFn blocks until the specific request that is being proxied is finished
type ProxyConnFn func()

// Handler is the type that all proxies need to implement to be called by the worker
// when a new client connection is created.  If there is an error ProxyConnFn must
// be nil. If there is no error ProxyConnFn must be set.  When Handler has
// returned, it is expected that the initial connection to the endpoint has been
// established.
type Handler func(context.Context, net.Conn, *ProxyDialer, string, *anypb.Any) (ProxyConnFn, error)

func RegisterHandler(protocol string, handler Handler) error {
	_, loaded := handlers.LoadOrStore(protocol, handler)
	if loaded {
		return ErrProtocolAlreadyRegistered
	}
	return nil
}

// GetHandler returns the handler registered for the provided protocol. If the protocol
// is not registered nil and ErrUnknownProtocol is returned.
func GetHandler(protocol string) (Handler, error) {
	handler, ok := handlers.Load(protocol)
	if !ok {
		return nil, ErrUnknownProtocol
	}
	return handler.(Handler), nil
}
