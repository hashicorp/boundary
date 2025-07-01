// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package gldap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/hashicorp/go-hclog"
)

// conn is a connection to an ldap client
type conn struct {
	mu sync.Mutex // mutex for the conn

	connID      int
	netConn     net.Conn
	logger      hclog.Logger
	router      *Mux
	shutdownCtx context.Context
	requestsWg  sync.WaitGroup

	reader   *bufio.Reader
	writer   *bufio.Writer
	writerMu sync.Mutex // shared lock across all ResponseWriter's to prevent write data races
}

// newConn will create a new Conn from an accepted net.Conn which will be used
// to serve requests to an ldap client.
func newConn(shutdownCtx context.Context, connID int, netConn net.Conn, logger hclog.Logger, router *Mux) (*conn, error) {
	const op = "gldap.NewConn"
	if shutdownCtx == nil {
		return nil, fmt.Errorf("%s: missing shutdown context: %w", op, ErrInvalidParameter)
	}
	if connID == 0 {
		return nil, fmt.Errorf("%s: missing connection id: %w", op, ErrInvalidParameter)
	}
	if netConn == nil {
		return nil, fmt.Errorf("%s: missing connection: %w", op, ErrInvalidParameter)
	}
	if logger == nil {
		return nil, fmt.Errorf("%s: missing logger: %w", op, ErrInvalidParameter)
	}
	if router == nil {
		return nil, fmt.Errorf("%s: missing router: %w", op, ErrInvalidParameter)
	}
	c := &conn{
		connID:      connID,
		netConn:     netConn,
		shutdownCtx: shutdownCtx,
		logger:      logger,
		router:      router,
	}
	if err := c.initConn(netConn); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return c, nil
}

// serveRequests until the connection is closed or the shutdownCtx is cancelled
// as the server stops
func (c *conn) serveRequests() error {
	const op = "gldap.serveRequests"

	requestID := 0
	for {
		requestID++
		w, err := newResponseWriter(c.writer, &c.writerMu, c.logger, c.connID, requestID)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}

		select {
		case <-c.shutdownCtx.Done():
			c.logger.Debug("received shutdown cancellation", "op", op, "conn", c.connID, "requestID", w.requestID)
			// build a request by hand, since this is not a normal situation
			// where we've read a request... and we need to make this check
			// before blocking on reading the next request.
			req := &Request{
				ID:           w.requestID,
				conn:         c,
				message:      &ExtendedOperationMessage{baseMessage: baseMessage{id: 0}},
				routeOp:      routeOperation(ExtendedOperationDisconnection),
				extendedName: ExtendedOperationDisconnection,
			}
			resp := req.NewResponse(WithResponseCode(ResultUnwillingToPerform), WithDiagnosticMessage("server stopping"))
			if err := w.Write(resp); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			if err := c.netConn.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			return nil
		default:
			// need a default to fall through to rest of loop...
		}
		r, err := c.readRequest(w.requestID)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "unexpected EOF") {
				return nil // connection is closed
			}
			return fmt.Errorf("%s: error reading request: %w", op, err)
		}

		switch {
		// TODO: rate limit in-flight requests per conn and send a
		// BusyResponse when the limit is reached.  This limit per conn
		// should be configurable

		case r.routeOp == unbindRouteOperation:
			// support an optional unbind route
			if c.router.unbindRoute != nil {
				c.router.unbindRoute.handler()(w, r)
			}
			// stop serving requests when UnbindRequest is received
			return nil

		// If it's a StartTLS request, then we can't dispatch it concurrently,
		// since the conn needs to complete it's TLS negotiation before handling
		// any other requests.
		// see: https://datatracker.ietf.org/doc/html/rfc4511#section-4.14.1
		case r.extendedName == ExtendedOperationStartTLS:
			c.router.serve(w, r)
		default:
			c.requestsWg.Add(1)
			go func() {
				defer func() {
					c.logger.Debug("requestsWg done", "op", op, "conn", c.connID, "requestID", w.requestID)
					c.requestsWg.Done()
				}()
				c.router.serve(w, r)
			}()
		}
	}
}

func (c *conn) readRequest(requestID int) (*Request, error) {
	const op = "gldap.(Conn).readRequest"

	p, err := c.readPacket(requestID)
	if err != nil {
		return nil, fmt.Errorf("%s: error reading packet for %d/%d: %w", op, c.connID, requestID, err)
	}
	r, err := newRequest(requestID, c, p)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create new in-memory request for %d/%d: %w", op, c.connID, requestID, err)
	}

	return r, nil
}

func (c *conn) readPacket(requestID int) (*packet, error) {
	const op = "gldap.readPacket"
	// read a request
	berPacket, err := func() (*ber.Packet, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		berPacket, err := ber.ReadPacket(c.reader)
		switch {
		case err != nil && strings.Contains(err.Error(), "invalid character for IA5String at pos 2"):
			return nil, fmt.Errorf("%s: error reading ber packet for %d/%d (possible attempt to use TLS with a non-TLS server): %w", op, c.connID, requestID, err)
		case err != nil:
			return nil, fmt.Errorf("%s: error reading ber packet for %d/%d: %w", op, c.connID, requestID, err)
		}
		return berPacket, nil
	}()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	p := &packet{Packet: berPacket}
	if c.logger.IsDebug() {
		c.logger.Debug("packet read", "op", op, "conn", c.connID, "requestID", requestID)
		p.Log(c.logger.StandardWriter(&hclog.StandardLoggerOptions{}), 0, false)
	}
	// Simple header is first... let's make sure it's an ldap packet with 2
	// children containing:
	//		[0] is a message ID
	//		[1] is a request header
	if err := p.basicValidation(); err != nil {
		return nil, fmt.Errorf("%s: failed validation: %w", op, err)
	}
	return p, nil
}

func (c *conn) initConn(netConn net.Conn) error {
	const op = "gldap.(Conn).initConn"
	if netConn == nil {
		return fmt.Errorf("%s: missing net conn: %w", op, ErrInvalidParameter)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.netConn = netConn
	c.reader = bufio.NewReader(c.netConn)
	c.writer = bufio.NewWriter(c.netConn)
	return nil
}

func (c *conn) close() error {
	const op = "gldap.(Conn).close"
	c.requestsWg.Wait()
	if err := c.netConn.Close(); err != nil {
		return fmt.Errorf("%s: error closing conn: %w", op, err)
	}
	return nil
}
