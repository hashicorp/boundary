// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cluster

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/protocol"
)

const sourceEventInfoString = "tracking listener source"

// trackingListener tracks a nodee connection in a DownstreamManager when a
// worker has connected successfully.
type trackingListener struct {
	ctx    context.Context
	ln     net.Listener
	dsm    *DownstreamManager
	source string
}

// NewTrackingListener returns a listener which adds all connections made
// through it to the provided DownstreamManager.  The net.Conn returned by
// Accept is only tracked if it is a *tls.Conn and was created by the
// nodeenrollment library. The source string is provided to add context to
// logs output by the NewTrackingListener.
func NewTrackingListener(ctx context.Context, l net.Listener, m *DownstreamManager, source string) (net.Listener, error) {
	const op = "common.NewTrackingListener"
	switch {
	case m == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil DownstreamManager")
	case l == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil base listener")
	}
	return &trackingListener{
		ctx:    ctx,
		ln:     l,
		dsm:    m,
		source: source,
	}, nil
}

// Accept satisfies the net.Listener interface.  If the wrapped listener
// must return a tls.Conn or an error is returned.  If the tls.Conn has no
// PeerCertificates then no error is returned and the Conn is not added to the
// DownstreamManager.
func (e *trackingListener) Accept() (net.Conn, error) {
	const op = "cluster.(trackingListener).Accept"
	conn, err := e.ln.Accept()
	if err != nil || conn == nil {
		return conn, err
	}

	eventingOpts := []any{sourceEventInfoString, e.source}
	var workerId string
	var tlsConn *tls.Conn
	switch c := conn.(type) {
	case *protocol.Conn:
		tlsConn = c.Conn
		wi, err := GetWorkerInfoFromStateMap(e.ctx, c)
		if err != nil || wi == nil || len(wi.WorkerId) == 0 {
			event.WriteSysEvent(e.ctx, op, "did not get worker information from state map")
			break
		}
		workerId = wi.WorkerId
		eventingOpts = append(eventingOpts, "worker id", workerId)
	case *tls.Conn:
		tlsConn = c
	default:
		event.WriteError(e.ctx, op, fmt.Errorf("unexpected connection type: %T", c), event.WithInfo(eventingOpts...))
		return conn, nil
	}

	if tlsConn == nil {
		event.WriteError(e.ctx, op, fmt.Errorf("nil tlsConn"), event.WithInfo(eventingOpts...))
		return conn, nil
	}
	if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
		event.WriteError(e.ctx, op, fmt.Errorf("tls conn without any peer certificates"), event.WithInfo(eventingOpts...))
		return conn, nil
	}

	keyId, err := nodee.KeyIdFromPkix(tlsConn.ConnectionState().PeerCertificates[0].SubjectKeyId)
	if err != nil {
		event.WriteError(e.ctx, op, err, event.WithInfo(sourceEventInfoString, e.source))
	}
	if keyId == "" {
		// No key id means there is nothing to track.
		event.WriteError(e.ctx, op, fmt.Errorf("no key id found for connection"), event.WithInfo(eventingOpts...))
		return conn, nil
	}
	eventingOpts = append(eventingOpts, "key_id", keyId)
	if len(workerId) > 0 {
		e.dsm.mapKeyToWorkerId(keyId, workerId)
	}
	e.dsm.addConnection(keyId, conn)
	event.WriteSysEvent(e.ctx, op, "tracking worker connection", eventingOpts...)

	return conn, nil
}

func (e *trackingListener) Close() error {
	return e.ln.Close()
}

func (e *trackingListener) Addr() net.Addr {
	return e.ln.Addr()
}
