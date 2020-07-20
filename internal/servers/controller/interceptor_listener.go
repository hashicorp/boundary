package controller

import (
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
		return nil, err
	}
	if m.c.logger.IsTrace() {
		m.c.logger.Trace("got connection", "addr", conn.RemoteAddr())
	}
	return conn, nil
}

func (m *interceptingListener) Close() error {
	return m.baseLn.Close()
}

func (m *interceptingListener) Addr() net.Addr {
	return m.baseLn.Addr()
}
