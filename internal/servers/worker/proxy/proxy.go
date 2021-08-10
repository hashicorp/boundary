package proxy

import (
	"context"
	"errors"
	"net"
	"sync"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/servers/worker/common"
	"github.com/hashicorp/boundary/internal/servers/worker/session"
	"nhooyr.io/websocket"
)

// Handler is the type that all proxies need to implement to be called by the worker
// when a new client connection is created.
type Handler func(ctx context.Context, clientAddr *net.TCPAddr, conn *websocket.Conn, cred common.CredentialData, sessionClient pbs.SessionServiceClient, si *session.Info, connectionId, endpoint string)

var (
	// handlers is the map of registered handlers
	handlers sync.Map

	// ErrUnknownProtocol specifies the provided protocol has no registered handler
	ErrUnknownProtocol = errors.New("proxy: handler not found for protocol")

	// ErrProtocolAlreadyRegistered specifies the provided protocol has already been registered
	ErrProtocolAlreadyRegistered = errors.New("proxy: protocol already registered")
)

// RegisterHandler registers the handler to call for the protocol. The protocol is
// negotiated when the connection was established to the worker.
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
