package cluster

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	nodee "github.com/hashicorp/nodeenrollment"
)

// trackingListener tracks a nodee connection in a DownstreamManager when a
// worker has connected successfully.
type trackingListener struct {
	ctx context.Context
	ln  net.Listener
	dsm *DownstreamManager
}

// NewTrackingListener returns a listener which adds all connections made
// through it to the provided DownstreamManager.  The net.Conn returned by
// Accept is only tracked if it is a *tls.Conn and was created by the
// nodeenrollment library.
func NewTrackingListener(ctx context.Context, l net.Listener, m *DownstreamManager) (net.Listener, error) {
	const op = "common.NewTrackingListener"
	switch {
	case m == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil DownstreamManager")
	case l == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil base listener")
	}
	return &trackingListener{
		ctx: ctx,
		ln:  l,
		dsm: m,
	}, nil
}

// Accept satisfies the net.Listener interface.  If the the wrapped listener
// must return a tls.Conn or an error is returned.  If the tls.Conn has no
// PeerCertificates then no error is returned and the Conn is not added to the
// DownstreamManager.
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
	if err != nil {
		// Create an error so it gets written out to the event log
		_ = errors.Wrap(e.ctx, err, op)
	}
	if keyId == "" {
		// No key id means there is nothing to track.
		return conn, nil
	}
	e.dsm.addConnection(keyId, conn)
	event.WriteSysEvent(e.ctx, op, "tracking worker connection", "key_id", keyId)

	return conn, nil
}

func (e *trackingListener) Close() error {
	return e.ln.Close()
}

func (e *trackingListener) Addr() net.Addr {
	return e.ln.Addr()
}
