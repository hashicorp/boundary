package common

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	nodee "github.com/hashicorp/nodeenrollment"
)

// EventingListener simply sends an event when a worker has connected
// successfully
type eventingListener struct {
	ctx    context.Context
	baseLn net.Listener
}

func NewEventingListener(ctx context.Context, baseLn net.Listener) (net.Listener, error) {
	const op = "common.(EventingListener).Accept"
	switch {
	case ctx == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil context")
	case baseLn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil base listener")
	}
	return &eventingListener{
		ctx:    ctx,
		baseLn: baseLn,
	}, nil
}

func (e *eventingListener) Accept() (net.Conn, error) {
	const op = "common.(EventingListener).Accept"
	conn, err := e.baseLn.Accept()
	if err != nil || conn == nil {
		return conn, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return conn, err
	}

	if tlsConn != nil && len(tlsConn.ConnectionState().PeerCertificates) > 0 {
		keyId, err := nodee.KeyIdFromPkix(tlsConn.ConnectionState().PeerCertificates[0].SubjectKeyId)
		if err == nil {
			event.WriteSysEvent(e.ctx, op, "worker successfully authenticated", "key_id", keyId)
		}
	}

	return conn, err
}

func (e *eventingListener) Close() error {
	return e.baseLn.Close()
}

func (e *eventingListener) Addr() net.Addr {
	return e.baseLn.Addr()
}
