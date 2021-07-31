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

	"github.com/hashicorp/boundary/internal/observability/event"
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
	cancel context.CancelFunc
	muxMap *sync.Map
}

func New(baseLn net.Listener) *ALPNMux {
	ctx, cancel := context.WithCancel(context.Background())
	ret := &ALPNMux{
		ctx:    ctx,
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

func (l *ALPNMux) RegisterProto(proto string, tlsConf *tls.Config) (net.Listener, error) {
	const op = "alpnmux.(ALPNMux).RegisterProto"
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

	return sub, nil
}

func (l *ALPNMux) UnregisterProto(proto string) {
	const op = "alpnmux.(ALPNMux).UnregisterProto"
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
	const op = "alpnmux.(ALPNMux).getConfigForClient"
	var ret *tls.Config

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
	const op = "alpnmux.(ALPNMux).accept"
	ctx := context.TODO()
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

		// Do the rest in a goroutine so that a timeout in e.g. handshaking
		// doesn't block acceptance of the next connection
		go func() {
			bufConn := &bufferedConn{
				Conn:   conn,
				buffer: bufio.NewReader(conn),
			}
			peeked, err := bufConn.buffer.Peek(3)
			if err != nil {
				bufConn.Close()
				return
			}
			switch {
			// First byte should always be a handshake, second byte a 3, and
			// third can be 3 or 1 depending on the implementation
			case peeked[0] != 0x16 || peeked[1] != 0x03 || (peeked[2] != 0x03 && peeked[2] != 0x01):
				val, ok := l.muxMap.Load(NoProto)
				if !ok {
					bufConn.Close()
					return
				}
				ml := val.(*muxedListener)
				ml.connMutex.RLock()
				if !ml.closed {
					ml.connCh <- bufConn
				}
				ml.connMutex.RUnlock()

			default:
				tlsConn := tls.Server(bufConn, baseTLSConf)
				if err := tlsConn.Handshake(); err != nil {
					closeErr := tlsConn.Close()
					if closeErr != nil {
						event.WriteError(ctx, op, err, event.WithInfoMsg("error handshaking connection", "addr", conn.RemoteAddr(), "close_error", closeErr))
					}
					return
				}
				negProto := tlsConn.ConnectionState().NegotiatedProtocol
				val, ok := l.muxMap.Load(negProto)
				if !ok {
					val, ok = l.muxMap.Load(DefaultProto)
					if !ok {
						tlsConn.Close()
						return
					}
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
