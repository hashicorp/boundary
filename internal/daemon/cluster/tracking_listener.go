// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cluster

import (
	"context"
	"crypto/tls"
	stderrors "errors"
	"fmt"
	"net"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/version"
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
		switch {
		case err != nil && errors.Is(err, errStateNotFound) && !version.SupportsFeature(version.Binary, version.RequireVersionInWorkerInfo):
			// This will cause us to break below
			wi = new(WorkerConnectionInfo)
		case err != nil:
			// We want to check that if we are supporting metadata that it is supplied
			innerErr := fmt.Errorf("error trying to get worker information from state map: %w", err)
			event.WriteError(e.ctx, op, innerErr)
			conn.Close()
			return conn, nil
		case wi == nil:
			event.WriteError(e.ctx, op, stderrors.New("nil worker info in state map"))
			conn.Close()
			return conn, nil
		case version.Get().VersionMetadata != "":
			incomingVer := version.FromVersionString(wi.BoundaryVersion)
			if (incomingVer == nil || incomingVer.VersionMetadata == "") && version.SupportsFeature(version.Binary, version.RequireVersionInWorkerInfo) {
				err := stderrors.New("build contains version with metadata, incoming worker version is nil or has mismatched metadata")
				event.WriteError(e.ctx, op, err)
				conn.Close()
				return conn, nil
			}
		}
		if len(wi.WorkerId) == 0 {
			event.WriteSysEvent(e.ctx, op, "did not find worker id in state map")
			break
		}
		workerId = wi.WorkerId
		eventingOpts = append(eventingOpts, "worker id", workerId)
	case *tls.Conn:
		tlsConn = c
	default:
		event.WriteError(e.ctx, op, fmt.Errorf("unexpected connection type: %T", c), event.WithInfo(eventingOpts...))
		conn.Close()
		return conn, nil
	}

	if tlsConn == nil {
		event.WriteError(e.ctx, op, fmt.Errorf("nil tlsConn"), event.WithInfo(eventingOpts...))
		conn.Close()
		return conn, nil
	}
	if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
		event.WriteError(e.ctx, op, fmt.Errorf("tls conn without any peer certificates"), event.WithInfo(eventingOpts...))
		conn.Close()
		return conn, nil
	}

	keyId, err := nodee.KeyIdFromPkix(tlsConn.ConnectionState().PeerCertificates[0].SubjectKeyId)
	if err != nil {
		event.WriteError(e.ctx, op, err, event.WithInfo(sourceEventInfoString, e.source))
	}
	if keyId == "" {
		// No key id means there is nothing to track.
		event.WriteError(e.ctx, op, stderrors.New("no key id found for connection"), event.WithInfo(eventingOpts...))
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
