package listener

import (
	"io"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/go-alpnmux"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/internalshared/listenerutil"
	"github.com/hashicorp/vault/internalshared/reloadutil"
	"github.com/mitchellh/cli"
)

func tcpListenerFactory(l *configutil.Listener, _ io.Writer, ui cli.Ui) (*alpnmux.ALPNMux, map[string]string, reloadutil.ReloadFunc, error) {
	if l.Address == "" {
		l.Address = "127.0.0.1:9200"
	}

	bindProto := "tcp"

	// If they've passed 0.0.0.0, we only want to bind on IPv4
	// rather than golang's dual stack default
	if strings.HasPrefix(l.Address, "0.0.0.0:") {
		bindProto = "tcp4"
	}

	ln, err := net.Listen(bindProto, l.Address)
	if err != nil {
		return nil, nil, nil, err
	}

	ln = TCPKeepAliveListener{ln.(*net.TCPListener)}

	ln, err = listenerWrapProxy(ln, l)
	if err != nil {
		return nil, nil, nil, err
	}

	props := map[string]string{
		"addr": l.Address,
	}

	alpnMux := alpnmux.New(ln, nil)

	if l.TLSDisable {
		if _, err = alpnMux.RegisterProto(alpnmux.NoProto, nil); err != nil {
			return nil, nil, nil, err
		}
		return alpnMux, props, nil, nil
	}

	tlsConfig, reloadFunc, err := listenerutil.GetTLSConfig(ln, l, props, ui)
	if err != nil {
		return nil, nil, nil, err
	}
	// Register no proto, "http/1.1", and "h2", with same TLS config
	if _, err = alpnMux.RegisterProto("", tlsConfig); err != nil {
		return nil, nil, nil, err
	}
	if _, err = alpnMux.RegisterProto("http/1.1", tlsConfig); err != nil {
		return nil, nil, nil, err
	}
	if _, err = alpnMux.RegisterProto("h2", tlsConfig); err != nil {
		return nil, nil, nil, err
	}

	return alpnMux, props, reloadFunc, nil
}

// TCPKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
//
// This is copied directly from the Go source code.
type TCPKeepAliveListener struct {
	*net.TCPListener
}

func (ln TCPKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
