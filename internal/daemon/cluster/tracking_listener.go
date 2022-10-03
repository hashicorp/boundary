package cluster

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
type trackingListener struct {
	ctx context.Context
	ln  net.Listener
	dsm *DownstreamManager
}

// NewTrackingListener returns a listener which adds all connections made
// through it to the provide DownstreamManager.  The net.Conn returned by
// Accept is only tracked if it is a *tls.Conn and was created the
// nodeenrollment library.
func NewTrackingListener(ctx context.Context, l net.Listener, m *DownstreamManager) (net.Listener, error) {
	const op = "common.(EventingListener).Accept"
	switch {
	case ctx == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil context")
	case l == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil base listener")
	}
	return &trackingListener{
		ctx: ctx,
		ln:  l,
		dsm: m,
	}, nil
}

func (e *trackingListener) Accept() (net.Conn, error) {
	const op = "cluster.(trackingListener).Accept"
	conn, err := e.ln.Accept()
	if err != nil || conn == nil {
		return conn, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return conn, err
	}

	if tlsConn == nil || len(tlsConn.ConnectionState().PeerCertificates) == 0 {
		return conn, nil
	}

	keyId, err := nodee.KeyIdFromPkix(tlsConn.ConnectionState().PeerCertificates[0].SubjectKeyId)
	if err == nil {
		event.WriteSysEvent(e.ctx, op, "worker successfully authenticated", "key_id", keyId)
	}
	e.dsm.addConnection(keyId, conn)
	event.WriteSysEvent(e.ctx, op, "tracking worker connection", "key_id", keyId)

	return conn, err
}

func (e *trackingListener) Close() error {
	return e.ln.Close()
}

func (e *trackingListener) Addr() net.Addr {
	return e.ln.Addr()
}
