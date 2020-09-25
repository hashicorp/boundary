package alpnmux

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
)

const (
	// NoProto is used when the connection isn't actually TLS
	NoProto = "(none)"

	// DefaultProto is used when there is an ALPN we don't actually know about.
	// If no protos are specified on an incoming TLS connection we will first
	// look for a proto of ""; if not found, will use DefaultProto. On a
	// connection that has protos defined, we will look for that proto first,
	// then DefaultProto.
	DefaultProto = "(*)"
)

type bufferedConn struct {
	net.Conn
	buffer *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.buffer.Read(p)
}

type muxedListener struct {
	connMutex *sync.RWMutex
	ctx       context.Context
	addr      net.Addr
	proto     string
	tlsConf   *tls.Config
	connCh    chan net.Conn
	closed    bool
	closeFunc func()
	closeOnce *sync.Once
}

type ALPNMux struct {
	ctx    context.Context
	baseLn net.Listener
	log    hclog.Logger
	cancel context.CancelFunc
	muxMap *sync.Map
}

func New(baseLn net.Listener, log hclog.Logger) *ALPNMux {
	ctx, cancel := context.WithCancel(context.Background())
	ret := &ALPNMux{
		ctx:    ctx,
		log:    log,
		cancel: cancel,
		muxMap: new(sync.Map),
		baseLn: baseLn,
	}
	go ret.accept()
	return ret
}

func (l *ALPNMux) Addr() net.Addr {
	return l.baseLn.Addr()
}

func (l *ALPNMux) Close() error {
	return l.baseLn.Close()
}

func (l *ALPNMux) SetLogger(log hclog.Logger) {
	l.log = log
}

func (l *ALPNMux) RegisterProto(proto string, tlsConf *tls.Config) (net.Listener, error) {
	switch proto {
	case NoProto:
		if tlsConf != nil {
			return nil, errors.New("tls config cannot be non-nil when using NoProto")
		}
	default:
		if tlsConf == nil {
			return nil, errors.New("nil tls config given")
		}
	}
	sub := &muxedListener{
		connMutex: new(sync.RWMutex),
		ctx:       l.ctx,
		addr:      l.baseLn.Addr(),
		proto:     proto,
		tlsConf:   tlsConf,
		connCh:    make(chan net.Conn),
		closeOnce: new(sync.Once),
	}
	_, loaded := l.muxMap.LoadOrStore(proto, sub)
	if loaded {
		close(sub.connCh)
		return nil, fmt.Errorf("proto %q already registered", proto)
	}

	sub.closeFunc = func() {
		go l.UnregisterProto(proto)
	}

	if l.log != nil && l.log.IsDebug() {
		l.log.Debug("registered", "proto", proto)
	}

	return sub, nil
}

func (l *ALPNMux) UnregisterProto(proto string) {
	val, ok := l.muxMap.Load(proto)
	if !ok {
		return
	}
	ml := val.(*muxedListener)
	ml.closeOnce.Do(func() {
		ml.connMutex.Lock()
		defer ml.connMutex.Unlock()
		ml.closed = true
		close(ml.connCh)
	})
	l.muxMap.Delete(proto)
	if l.log != nil && l.log.IsDebug() {
		l.log.Debug("unregistered", "proto", proto)
	}
}

func (l *ALPNMux) GetListener(proto string) net.Listener {
	val, ok := l.muxMap.Load(proto)
	if !ok || val == nil {
		val, ok = l.muxMap.Load(DefaultProto)
		if !ok || val == nil {
			return nil
		}
	}
	return val.(*muxedListener)
}

func (l *ALPNMux) getConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	var ret *tls.Config

	if l.log != nil && l.log.IsTrace() {
		l.log.Trace("getting config for client", "supported_protos", hello.SupportedProtos, "server_name", hello.ServerName)
	}

	supportedProtos := hello.SupportedProtos
	if len(hello.SupportedProtos) == 0 {
		supportedProtos = append(supportedProtos, "")
	}
	for _, proto := range supportedProtos {
		val, ok := l.muxMap.Load(proto)
		if !ok {
			continue
		}
		ret = val.(*muxedListener).tlsConf
	}
	if ret == nil {
		val, ok := l.muxMap.Load(DefaultProto)
		if ok && val != nil {
			ret = val.(*muxedListener).tlsConf
		}
	}
	if ret == nil {
		return nil, errors.New("no tls configuration available for any client protos")
	}

	// If the TLS config we found has its own lookup function, chain to it
	if ret.GetConfigForClient != nil {
		return ret.GetConfigForClient(hello)
	}

	return ret, nil
}

func (l *ALPNMux) accept() {
	baseTLSConf := &tls.Config{
		GetConfigForClient: l.getConfigForClient,
	}
	for {
		conn, err := l.baseLn.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				l.cancel()
				return
			}
		}
		if conn == nil {
			continue
		}
		if l.log != nil && l.log.IsTrace() {
			l.log.Trace("got connection", "addr", conn.RemoteAddr())
		}

		// Do the rest in a goroutine so that a timeout in e.g. handshaking
		// doesn't block acceptance of the next connection
		go func() {
			bufConn := &bufferedConn{
				Conn:   conn,
				buffer: bufio.NewReader(conn),
			}
			peeked, err := bufConn.buffer.Peek(3)
			if err != nil {
				if l.log != nil && l.log.IsDebug() {
					l.log.Debug("error peeking connection", "addr", conn.RemoteAddr(), "error", err)
				}
				bufConn.Close()
				return
			}
			switch {
			// First byte should always be a handshake, second byte a 3, and
			// third can be 3 or 1 depending on the implementation
			case peeked[0] != 0x16 || peeked[1] != 0x03 || (peeked[2] != 0x03 && peeked[2] != 0x01):
				if l.log != nil && l.log.IsTrace() {
					l.log.Trace("connection is not tls", "addr", conn.RemoteAddr())
				}
				val, ok := l.muxMap.Load(NoProto)
				if !ok {
					if l.log != nil && l.log.IsTrace() {
						l.log.Trace("no non-tls registration found", "addr", conn.RemoteAddr())
					}
					bufConn.Close()
					return
				}
				if l.log != nil && l.log.IsTrace() {
					l.log.Trace("found noproto handler", "addr", conn.RemoteAddr())
				}
				ml := val.(*muxedListener)
				ml.connMutex.RLock()
				if !ml.closed {
					ml.connCh <- bufConn
				}
				ml.connMutex.RUnlock()

			default:
				if l.log != nil && l.log.IsTrace() {
					l.log.Trace("connection is tls", "addr", conn.RemoteAddr())
				}
				tlsConn := tls.Server(bufConn, baseTLSConf)
				if l.log != nil && l.log.IsTrace() {
					l.log.Trace("handshaking", "addr", conn.RemoteAddr())
				}
				if err := tlsConn.Handshake(); err != nil {
					closeErr := tlsConn.Close()
					if l.log != nil && l.log.IsDebug() {
						l.log.Debug("error handshaking connection", "addr", conn.RemoteAddr(), "error", err, "close_error", closeErr)
					}
					return
				}
				negProto := tlsConn.ConnectionState().NegotiatedProtocol
				if l.log != nil && l.log.IsTrace() {
					l.log.Trace("tls negotiated", "addr", conn.RemoteAddr(), "proto", negProto)
				}
				val, ok := l.muxMap.Load(negProto)
				if !ok {
					val, ok = l.muxMap.Load(DefaultProto)
					if !ok {
						if l.log != nil && l.log.IsTrace() {
							l.log.Trace("no handler found", "addr", conn.RemoteAddr(), "proto", negProto)
						}
						tlsConn.Close()
						return
					}
				}
				if l.log != nil && l.log.IsTrace() {
					l.log.Trace("found tls handler", "addr", conn.RemoteAddr(), "proto", negProto)
				}
				ml := val.(*muxedListener)
				ml.connMutex.RLock()
				if !ml.closed {
					ml.connCh <- tlsConn
				}
				ml.connMutex.RUnlock()
			}
		}()
	}
}

func (m *muxedListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-m.ctx.Done():
			// Wouldn't it be so much better if this error was an exported
			// const from Go...
			m.closeFunc()
			return nil, fmt.Errorf("accept proto %s: use of closed network connection", m.proto)
		case conn, ok := <-m.connCh:
			if !ok {
				// Channel closed
				return nil, fmt.Errorf("accept proto %s: use of closed network connection", m.proto)
			}
			if conn == nil {
				return nil, fmt.Errorf("accept proto %s: nil connection received", m.proto)
			}
			return conn, nil
		}
	}
}

func (m *muxedListener) Close() error {
	m.closeFunc()
	return nil
}

func (m *muxedListener) Addr() net.Addr {
	return m.addr
}
