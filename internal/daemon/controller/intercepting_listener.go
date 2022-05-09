package controller

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/boundary/internal/observability/event"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/nodeauth"
)

// interceptingListener allows us to validate the nonce from a connection before
// handing it off to the gRPC server. It is expected that the first thing a
// connection sends after successful TLS validation is the nonce that was
// contained in the KMS-encrypted TLS info. The reason is for replay attacks --
// since the ALPN NextProtos are sent in the clear, we don't want anyone
// sniffing the connection to simply replay the hello message and gain access.
// By requiring the information encrypted within that message to match the first
// bytes sent in the connection itself, we require that the service making the
// incoming connection had to either be the service that did the initial
// encryption, or had to be able to decrypt that against the same KMS key. This
// means that KMS access is a requirement, and simple replay itself is not
// sufficient.
//
// Note that this is semi-weak against a scenario where the value is decrypted
// later since a controller restart would clear the cache. We could store a list
// of seen nonces in the database, but since the original certificate was only
// good for 3 minutes and 30 seconds anyways, the decryption would need to
// happen within a short time window instead of much later. We can adjust this
// window if we want (or even make it tunable), or store values in the DB as
// well until the certificate expiration.
type interceptingListener struct {
	baseLn net.Listener
	c      *Controller
}

func newInterceptingListener(c *Controller, baseLn net.Listener) *interceptingListener {
	ret := &interceptingListener{
		c:      c,
		baseLn: baseLn,
	}

	return ret
}

func (m *interceptingListener) Accept() (net.Conn, error) {
	const op = "controller.(interceptingListener).Accept"
	ctx := m.c.baseContext
	conn, err := m.baseLn.Accept()
	if err != nil {
		// We may already be closed but can't be sure, so just try anyways
		if conn != nil {
			if err := conn.Close(); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing worker connection"))
			}
		}
		return nil, err
	}

	tlsConn := conn.(*tls.Conn)
	switch {
	case nodeauth.ContainsNodeAuthAlpnProto(tlsConn.ConnectionState().NegotiatedProtocol):
		event.WriteSysEvent(ctx, op, "worker successfully authed", "key_id", nodee.KeyIdFromPkix(tlsConn.ConnectionState().PeerCertificates[0].SubjectKeyId))
		return conn, nil

	case strings.HasPrefix(tlsConn.ConnectionState().NegotiatedProtocol, "v1workerauth"):
		nonce := make([]byte, 20)
		read, err := conn.Read(nonce)
		if err != nil {
			if err := conn.Close(); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing worker connection"))
			}
			return nil, fmt.Errorf("error reading nonce from connection: %w", err)
		}
		if read != len(nonce) {
			if err := conn.Close(); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing worker connection"))
			}
			return nil, fmt.Errorf("error reading nonce from worker, expected %d bytes, got %d", 20, read)
		}
		workerInfoRaw, found := m.c.workerAuthCache.Load(string(nonce))
		if !found {
			if err := conn.Close(); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("error closing worker connection"))
			}
			return nil, errors.New("did not find valid nonce for incoming worker")
		}
		workerInfo := workerInfoRaw.(*workerAuthEntry)
		workerInfo.conn = tlsConn
		event.WriteSysEvent(ctx, op, "worker successfully authed", "name", workerInfo.Name)
		return tlsConn, nil

	default:
		return nil, nodeauth.NewTempError(errors.New("unable to authenticate incoming connection"))
	}
}

func (m *interceptingListener) Close() error {
	return m.baseLn.Close()
}

func (m *interceptingListener) Addr() net.Addr {
	return m.baseLn.Addr()
}
