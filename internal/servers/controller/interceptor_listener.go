package controller

import (
	"errors"
	"fmt"
	"net"
)

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
