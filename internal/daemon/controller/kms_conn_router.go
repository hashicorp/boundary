// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	nodeenet "github.com/hashicorp/nodeenrollment/net"
)

// tempError is an error that satisfies the temporary error interface that is
// internally used by gRPC to determine whether an error should cause a listener
// to die. Any error that isn't an accept error is wrapped in this since one
// connection failing TLS wise doesn't mean we don't want to accept any more...
type tempError struct {
	error
}

// newTempError is a "temporary" error
func newTempError(inner error) tempError {
	return tempError{error: inner}
}

func (t tempError) Temporary() bool {
	return true
}

// startKmsConnRouter allows us to validate the nonce from a connection before
// handing it off to other purposes, such as the gRPC server. It is expected
// that the first thing a connection sends after successful TLS validation is
// the nonce that was contained in the KMS-encrypted TLS info. The reason is for
// replay attacks -- since the ALPN NextProtos are sent in the clear, we don't
// want anyone sniffing the connection to simply replay the hello message and
// gain access. By requiring the information encrypted within that message to
// match the first bytes sent in the connection itself, we require that the
// service making the incoming connection had to either be the service that did
// the initial encryption, or had to be able to decrypt that against the same
// KMS key. This means that KMS access is a requirement, and simple replay
// itself is not sufficient.
func startKmsConnRouter(
	ctx context.Context,
	c *Controller,
	baseLn net.Listener,
	authedListener,
	reverseGrpcListener *nodeenet.MultiplexingListener,
) error {
	const op = "controller.startKmsAuthRouter"
	switch {
	case c == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "nil Controller")
	case baseLn == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "nil baseLn")
	case authedListener == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "nil authedListener")
	case reverseGrpcListener == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "nil reverseGrpcListener")
	}

	go func() {
		for {
			conn, err := baseLn.Accept()
			if err != nil {
				if err == net.ErrClosed {
					// We're done
					return
				}
				// Conn may already be closed but can't be sure, so just try anyways
				if conn != nil {
					if err := conn.Close(); err != nil {
						event.WriteError(ctx, op, err, event.WithInfoMsg("error closing worker connection"))
					}
				}
				event.WriteError(ctx, op, err, event.WithInfoMsg("error accepting kms connection"))
				continue
			}

			if conn == nil {
				// No idea why this would happen, but be safe before we operate
				// on it below
				event.WriteError(ctx, op, fmt.Errorf("connection is nil"))
				continue
			}

			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				// This should never happen, but is just to be safe
				event.WriteError(ctx, op, fmt.Errorf("connection is not a *tls.Conn"))
				_ = conn.Close()
				continue
			}

			if !strings.HasPrefix(tlsConn.ConnectionState().NegotiatedProtocol, "v1workerauth") {
				// If we're here it hasn't been handled by PKI and can't be
				// handled here. We should never actually get here...
				event.WriteError(ctx, op, fmt.Errorf("connection is not a kms connection"))
				_ = conn.Close()
				continue
			}

			nonce := make([]byte, 20)
			read, err := conn.Read(nonce)
			if err != nil {
				if err := conn.Close(); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error closing worker connection"))
				}
				event.WriteError(ctx, op, err, event.WithInfoMsg("error reading nonce from connection"))
				continue
			}
			if read != len(nonce) {
				if err := conn.Close(); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error closing worker connection"))
				}
				event.WriteError(ctx, op, fmt.Errorf("error reading nonce from worker, expected %d bytes, got %d", 20, read))
				continue
			}

			workerInfoRaw, found := c.workerAuthCache.Load(string(nonce))
			if !found {
				if err := conn.Close(); err != nil {
					event.WriteError(ctx, op, err, event.WithInfoMsg("error closing worker connection"))
				}
				event.WriteError(ctx, op, fmt.Errorf("did not find valid nonce for incoming worker"))
				continue
			}

			workerInfo := workerInfoRaw.(*workerAuthEntry)
			workerInfo.conn = tlsConn
			c.workerAuthCache.Delete(string(nonce))
			event.WriteSysEvent(ctx, op, "worker successfully authed", "name", workerInfo.Name, "description", workerInfo.Description, "proxy_address", workerInfo.ProxyAddress)

			found = false
			for _, proto := range workerInfo.clientNextProtos {
				if proto == common.ReverseGrpcConnectionAlpnValue {
					reverseGrpcListener.IngressConn(tlsConn, nil)
					found = true
					break
				}
			}
			if found {
				continue
			}
			// Didn't find specific ALPN values, so it's a normal grpc
			// connection
			authedListener.IngressConn(tlsConn, nil)
		}
	}()
	return nil
}
