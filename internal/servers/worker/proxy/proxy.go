package proxy

import (
	"context"
	"errors"
	"net"
	"sync"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/servers/worker/session"
	"nhooyr.io/websocket"
)

// Config provides the core parameters needed for a worker to create a proxy between
// a provided ClientConn and the RemoteEndpoint, as well as the parameters to update
// the connection in the connection repository.
type Config struct {
	// UserClientIp is the user's client IP
	UserClientIp string
	// ClientAddress is the remote address (IP and port) of the client.  If
	// there are any load balancers or proxies between the user and the worker,
	// then it will be the address of the last one before the worker.
	ClientAddress  *net.TCPAddr
	ClientConn     *websocket.Conn
	RemoteEndpoint string

	SessionClient pbs.SessionServiceClient
	SessionInfo   *session.Info
	ConnectionId  string
}

// Validate checks that the provided config is valid. If invalid, an error is returned
// specifying the error.
func (c Config) Validate() error {
	switch {
	case c.ClientAddress == nil:
		return errors.New("missing client address")
	case c.ClientConn == nil:
		return errors.New("missing client connection")
	case c.RemoteEndpoint == "":
		return errors.New("missing remote endpoint")
	case c.SessionClient == nil:
		return errors.New("missing session client")
	case c.SessionInfo == nil:
		return errors.New("missing session info")
	case c.ConnectionId == "":
		return errors.New("missing connection id")
	default:
		return nil
	}
}

// Handler is the type that all proxies need to implement to be called by the worker
// when a new client connection is created.
type Handler func(ctx context.Context, config Config, opt ...Option) error

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
