// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package net

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/protocol"
)

const (
	UnauthenticatedNextProto          = "__UNAUTH__"
	AuthenticatedNonSpecificNextProto = "__AUTH__"
)

// SplitListener can be useful for integration with systems that expect to do
// their own handling of connections off of a net.Listener. One such example is
// gRPC which expects to be handed a listener and has deprecated any ability to
// simply hand it a connection. GetListener can be called with
// AuthenticatedNonSpecificNextProto which in turn can be given to the gRPC
// server to pass authenticated connections to gRPC, and a listener with
// UnauthenticatedNextProto can be passed to another handler.
//
// SplitListener is compatible with the protocol package's Dialer's
// WithExtraAlpnProtos option. As the base listener is a *protocol.Listener, the
// client-specified NextProtos will be passed through to here and used to allow
// further switching based on listeners retrieved from GetListener with custom
// protos.
//
// Regardless of client-specified NextProto or not, any connection that's
// returned from a listener retrieved from GetListener will always have been
// authenticated with NodeEnrollment _unless_ they are coming from an
// UnauthenticatedNextProto listener.
//
// On receiving an error from the underlying Accept from the base listener that
// is not a Temporary error, the listener will stop listening.
type SplitListener struct {
	baseLn        *protocol.InterceptingListener
	babyListeners *sync.Map
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewSplitListener creates a new listener from a base listener, which must be a
// *protocol.InterceptingListener.
func NewSplitListener(baseLn net.Listener) (*SplitListener, error) {
	const op = "nodeenrollment.net.NewSplitListener"
	intLn, ok := baseLn.(*protocol.InterceptingListener)
	if !ok {
		return nil, fmt.Errorf("(%s): listener is not a *protocol.InterceptingListener", op)
	}

	l := &SplitListener{
		baseLn:        intLn,
		babyListeners: new(sync.Map),
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	return l, nil
}

// Start starts the listener running. It will run until the base listener is
// closed, causing Accept to return a non-temporary error.
//
// Any temporary errors encountered will cause just that connection to be
// closed.
func (l *SplitListener) Start() error {
	defer func() {
		l.babyListeners.Range(func(k, v any) bool {
			v.(*MultiplexingListener).Close()
			return true
		})
	}()
	for {
		conn, err := l.baseLn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				l.cancel()
				return err
			}
			if tempErr, ok := err.(interface {
				Temporary() bool
			}); ok && tempErr.Temporary() {
				continue
			}
			l.cancel()
			return err
		}

		protoConn, ok := conn.(*protocol.Conn)
		if !ok {
			// It'd be nice not to be silent about this, but since we've
			// verified that only *protocol.InterceptingListener can be the
			// underlying listener, this should never really happen
			_ = conn.Close()
			continue
		}

		tlsConn := protoConn.Conn
		if !tlsConn.ConnectionState().HandshakeComplete {
			// Another case where assuming it is in fact the listener we expect,
			// it will always have performed a handshake as the protocol
			// requires it; so it'd be nice not to be silent about this, but
			// this should never really happen
			_ = conn.Close()
			continue
		}

		negProto := tlsConn.ConnectionState().NegotiatedProtocol
		if nodeenrollment.ContainsKnownAlpnProto(negProto) {
			if strings.HasPrefix(negProto, nodeenrollment.FetchNodeCredsNextProtoV1Prefix) {
				// If it's the fetch proto, the TLS handshake should be all that is
				// needed and the connection should be closed already. Close it for
				// safety and continue.
				_ = conn.Close()
				continue
			}

			// Get client conns and do a search
			clientNextProtos := protoConn.ClientNextProtos()
			var foundListener *MultiplexingListener
			l.babyListeners.Range(func(k, v any) bool {
				for _, proto := range clientNextProtos {
					if k.(string) == proto {
						foundListener = v.(*MultiplexingListener)
						return false
					}
				}
				return true
			})

			// If we didn't find something for that proto, look for a
			// non-specific authenticated listener
			if foundListener == nil {
				val, ok := l.babyListeners.Load(AuthenticatedNonSpecificNextProto)
				if ok {
					foundListener = val.(*MultiplexingListener)
				}
			}

			// If we found a listener send the conn down, otherwise close the
			// conn
			if foundListener == nil {
				_ = conn.Close()
			} else {
				foundListener.IngressConn(protoConn, nil)
			}
			continue
		}

		// Not authenticated
		val, ok := l.babyListeners.Load(UnauthenticatedNextProto)
		if !ok {
			_ = conn.Close()
		} else {
			val.(*MultiplexingListener).IngressConn(protoConn, nil)
		}
	}
}

// GetListener returns a listener that will return connections that satisfy both
// of the following:
//
// * It has been authenticated with the nodeenrollment library
//
// * The client handshake contained an ALPN NextProto value that has the given
// value (e.g. protocol.Dialer had the WithExtraAlpnProtos option specified)
//
// There are two special values:
//
// * If the given value is the AuthenticatedNonSpecificNextProto const value,
// any authenticated connection that does not match a specific value is returned
//
// * If the given value is the UnauthenticatedNextProto const value, any
// connection that is not authenticated by the nodeenrollment library will be
// returned on it. This includes connections that did not successfully TLS
// handshake or that are not TLS connections.
//
// The connections returned over the listener will always be `*tls.Conn` unless
// WithNativeConns is specified in which case it will be `*protocol.Conn`
//
// If there was a previous listener for the given value, it is returned,
// otherwise a new one is created.
//
// Don't call GetListener after the underlying listener has been closed; this
// will result in an unclosed channel if there is a race.
//
// Supported options: WithNativeConns
func (l *SplitListener) GetListener(nextProto string, opt ...nodeenrollment.Option) (net.Listener, error) {
	const op = "nodeenrollment.net.(SplitListener).GetListener"
	if nextProto == "" {
		return nil, fmt.Errorf("(%s): missing next proto value", op)
	}
	if l.ctx.Err() != nil {
		return nil, net.ErrClosed
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s): error parsing opts: %w", op, err)
	}

	newMultiplexingListener, err := NewMultiplexingListener(l.ctx, l.baseLn.Addr(), opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s): error creating multiplexing listener: %w", op, err)
	}
	newMultiplexingListener.nativeConns = new(bool)
	*newMultiplexingListener.nativeConns = opts.WithNativeConns

	existing, loaded := l.babyListeners.LoadOrStore(nextProto, newMultiplexingListener)
	if loaded {
		_ = newMultiplexingListener.Close()
		return existing.(*MultiplexingListener), nil
	}
	return newMultiplexingListener, nil
}

type splitConn struct {
	conn net.Conn
	err  error
}

// MultiplexingListener presents a listener interface, with connections sourced
// from direct function calls or listeners passed in.
//
// Always use NewMultiplexingListener to create an instance. Failure to do so may
// result in an eventual runtime panic.
type MultiplexingListener struct {
	addr         net.Addr
	incoming     chan splitConn
	ctx          context.Context
	cancel       context.CancelFunc
	drainSpawned *sync.Once
	nativeConns  *bool
	closedMutex  *sync.RWMutex
	closedOnce   *sync.Once
	closed       bool
}

// NewMultiplexingListener creates a new listener with the given context for
// canceling. It will report the given address when the net.Listener.Addr()
// function is called.
func NewMultiplexingListener(ctx context.Context, addr net.Addr, opt ...nodeenrollment.Option) (*MultiplexingListener, error) {
	const op = "nodeenrollment.net.NewMultiplexingListener"
	switch {
	case nodeenrollment.IsNil(ctx):
		return nil, fmt.Errorf("(%s): nil context", op)
	case nodeenrollment.IsNil(addr):
		return nil, fmt.Errorf("(%s): nil addr", op)
	}

	multiplexer := &MultiplexingListener{
		addr:         addr,
		incoming:     make(chan splitConn),
		drainSpawned: new(sync.Once),
		closedMutex:  new(sync.RWMutex),
		closedOnce:   new(sync.Once),
	}
	multiplexer.ctx, multiplexer.cancel = context.WithCancel(ctx)

	return multiplexer, nil
}

// Addr satisfies the net.Listener interface and returns the base listener
// address
func (l *MultiplexingListener) Addr() net.Addr {
	return l.addr
}

// Close satisfies the net.Listener interface and closes this specific listener.
// We call drainConnections here to ensure that senders don't block even though
// we're no longer accepting them.
func (l *MultiplexingListener) Close() error {
	l.drainConnections()
	l.closedMutex.Lock()
	l.closed = true
	l.closedOnce.Do(func() { close(l.incoming) })
	l.closedMutex.Unlock()
	return nil
}

// Accept satisfies the net.Listener interface and returns the next connection
// that has been sent to this listener, or net.ErrClosed if the listener has
// been closed.
func (l *MultiplexingListener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		// If Close() was called this would happen anyways, but in case it
		// was only called on the parent context, ensure we drain
		// connections
		l.drainConnections()
		return nil, net.ErrClosed

	case in, ok := <-l.incoming:
		if !ok || nodeenrollment.IsNil(in.conn) {
			// Channel has been closed
			return nil, net.ErrClosed
		}

		select {
		case <-l.ctx.Done():
			// Check one more time in case this was pseduo-randomly chosen as
			// the valid case and the context is done; if so close the conn and
			// return ErrClosed
			_ = in.conn.Close()
			return nil, net.ErrClosed
		default:
		}

		switch {
		case in.conn == nil,
			// ^ Probably error, pass through
			l.nativeConns == nil,
			// ^ Wasn't created via GetListener so don't potentially strip,
			// pass through
			*l.nativeConns:
			// ^ Created via GetListener but told to use whatever we were
			// given, so pass straight through
			return in.conn, in.err

		default:
			// *l.nativeConns is false, so check if it's a *protocol.Conn to
			// pull out the *tls.Conn
			if native, ok := in.conn.(*protocol.Conn); ok {
				// Strip the tls conn out of the package conn
				return native.Conn, in.err
			}
			// Some other type (maybe already *tls.Conn), just return
			return in.conn, in.err
		}
	}
}

// IngressListener will read connections off the given listener until the listener
// is closed and returns net.ErrClosed; any other error during listen will be
// sent through as-is. Any conns will be put onto the internal channel. This
// function does not block; it will only ever error if the listener is nil.
func (l *MultiplexingListener) IngressListener(ln net.Listener) error {
	const op = "nodeenrollment.net.(multiplexingListener).IngressListener"
	if ln == nil {
		return fmt.Errorf("%s: nil listener", op)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			l.closedMutex.RLock()
			if l.closed {
				conn.Close()
				l.closedMutex.RUnlock()
				return
			}
			l.incoming <- splitConn{conn: conn, err: err}
			l.closedMutex.RUnlock()
		}
	}()

	return nil
}

// IngressConn sends a connection and associated error through the listener
// as-is. It does not perform any nil checking on the given values.
func (l *MultiplexingListener) IngressConn(conn net.Conn, err error) {
	l.closedMutex.RLock()
	defer l.closedMutex.RUnlock()
	if l.closed {
		conn.Close()
		return
	}
	l.incoming <- splitConn{conn: conn, err: err}
}

// drainConnections ensures we close any connections sent our way once the
// listener is closed so no open connections leak
func (l *MultiplexingListener) drainConnections() {
	if l.cancel != nil {
		l.cancel()
	}
	if l.drainSpawned != nil {
		l.drainSpawned.Do(func() {
			go func() {
				for in := range l.incoming {
					if in.conn != nil {
						_ = in.conn.Close()
					}
				}
			}()
		})
	}
}
