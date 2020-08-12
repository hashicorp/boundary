package controller

import (
	"errors"
	"fmt"
	"net"
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
	conn, err := m.baseLn.Accept()
	if err != nil {
		if conn != nil {
			if err := conn.Close(); err != nil {
				m.c.logger.Error("error closing worker connection", "error", err)
			}
		}
		return nil, err
	}
	if m.c.logger.IsTrace() {
		m.c.logger.Trace("got connection", "addr", conn.RemoteAddr())
	}
	nonce := make([]byte, 20)
	read, err := conn.Read(nonce)
	if err != nil {
		if err := conn.Close(); err != nil {
			m.c.logger.Error("error closing worker connection", "error", err)
		}
		return nil, fmt.Errorf("error reading nonce from connection: %w", err)
	}
	if read != len(nonce) {
		if err := conn.Close(); err != nil {
			m.c.logger.Error("error closing worker connection", "error", err)
		}
		return nil, fmt.Errorf("error reading nonce from worker, expected %d bytes, got %d", 20, read)
	}
	workerInfoRaw, found := m.c.workerAuthCache.Get(string(nonce))
	if !found {
		if err := conn.Close(); err != nil {
			m.c.logger.Error("error closing worker connection", "error", err)
		}
		return nil, errors.New("did not find valid nonce for incoming worker")
	}
	workerInfo := workerInfoRaw.(*workerAuthEntry)
	workerInfo.conn = conn
	m.c.logger.Info("worker successfully authed", "name", workerInfo.Name)
	return conn, nil
}

func (m *interceptingListener) Close() error {
	return m.baseLn.Close()
}

func (m *interceptingListener) Addr() net.Addr {
	return m.baseLn.Addr()
}
