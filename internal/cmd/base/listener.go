package base

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	// We must import sha512 so that it registers with the runtime so that
	// certificates that use it can be parsed.
	_ "crypto/sha512"

	"github.com/hashicorp/boundary/internal/libs/alpnmux"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/mitchellh/cli"
	"github.com/pires/go-proxyproto"
	"google.golang.org/grpc"
)

type ServerListener struct {
	Mux          *alpnmux.ALPNMux
	Config       *listenerutil.ListenerConfig
	HTTPServer   *http.Server
	GrpcServer   *grpc.Server
	ALPNListener net.Listener
}

type WorkerAuthInfo struct {
	CertPEM         []byte `json:"cert"`
	KeyPEM          []byte `json:"key"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	ConnectionNonce string `json:"connection_nonce"`
}

// Factory is the factory function to create a listener.
type ListenerFactory func(string, *listenerutil.ListenerConfig, cli.Ui) (string, net.Listener, error)

// BuiltinListeners is the list of built-in listener types.
var BuiltinListeners = map[string]ListenerFactory{
	"tcp":  tcpListenerFactory,
	"unix": unixListenerFactory,
}

// New creates a new listener of the given type with the given
// configuration. The type is looked up in the BuiltinListeners map.
func NewListener(l *listenerutil.ListenerConfig, ui cli.Ui) (*alpnmux.ALPNMux, map[string]string, reloadutil.ReloadFunc, error) {
	f, ok := BuiltinListeners[l.Type]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown listener type: %q", l.Type)
	}

	if len(l.Purpose) != 1 {
		return nil, nil, nil, fmt.Errorf("expected single listener purpose, found %d", len(l.Purpose))
	}
	purpose := l.Purpose[0]

	switch purpose {
	case "cluster":
		l.TLSDisable = true
	case "proxy":
		// TODO: Eventually we'll support bringing your own cert, and we'd only
		// want to disable if you aren't actually bringing your own
		l.TLSDisable = true
	default:
		switch l.TLSMinVersion {
		case "", "tls12", "tls13":
		default:
			return nil, nil, nil, fmt.Errorf("unsupported minimum tls version %q", l.TLSMinVersion)
		}
		switch l.TLSMaxVersion {
		case "", "tls12", "tls13":
		default:
			return nil, nil, nil, fmt.Errorf("unsupported maximum tls version %q", l.TLSMaxVersion)
		}
	}

	finalAddr, ln, err := f(purpose, l, ui)
	if err != nil {
		return nil, nil, nil, err
	}

	ln, err = listenerWrapProxy(ln, l)
	if err != nil {
		return nil, nil, nil, err
	}

	props := map[string]string{
		"addr": finalAddr,
	}

	alpnMux := alpnmux.New(ln)

	if l.TLSDisable {
		return alpnMux, props, nil, nil
	}

	// Don't request a client cert unless they've explicitly configured it to do
	// so
	if !l.TLSRequireAndVerifyClientCert {
		l.TLSDisableClientCerts = true
	}
	tlsConfig, reloadFunc, err := listenerutil.TLSConfig(l, props, ui)
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

func tcpListenerFactory(purpose string, l *listenerutil.ListenerConfig, ui cli.Ui) (string, net.Listener, error) {
	if l.Address == "" {
		switch purpose {
		case "cluster":
			l.Address = "127.0.0.1:9201"
		case "proxy":
			l.Address = "127.0.0.1:9202"
		case "ops":
			l.Address = "127.0.0.1:9203"
		default:
			l.Address = "127.0.0.1:9200"
		}
	}

	host, port, err := net.SplitHostPort(l.Address)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			switch purpose {
			case "cluster":
				port = "9201"
			case "proxy":
				port = "9202"
			case "ops":
				port = "9203"
			default:
				port = "9200"
			}
			host = l.Address
		} else {
			return "", nil, fmt.Errorf("error splitting host/port: %w", err)
		}
	}

	if host == "" {
		return "", nil, errors.New("could not determine host")
	}
	if port == "" {
		return "", nil, errors.New("could not determine port")
	}

	bindProto := "tcp"

	// If they've passed 0.0.0.0, we only want to bind on IPv4
	// rather than golang's dual stack default
	if strings.HasPrefix(l.Address, "0.0.0.0:") || l.Address == "0.0.0.0" {
		bindProto = "tcp4"
	}

	if l.RandomPort {
		port = ""
	}

	finalListenAddr := net.JoinHostPort(host, port)

	ln, err := net.Listen(bindProto, finalListenAddr)
	if err != nil {
		return "", nil, err
	}

	// If we used a random port, for a test, we need to save it back so we can set the public address appropriately
	if l.RandomPort {
		l.Address = ln.Addr().String()
	}

	ln = TCPKeepAliveListener{ln.(*net.TCPListener)}

	return finalListenAddr, ln, nil
}

func unixListenerFactory(purpose string, l *listenerutil.ListenerConfig, ui cli.Ui) (string, net.Listener, error) {
	var uConfig *listenerutil.UnixSocketsConfig
	if l.SocketMode != "" &&
		l.SocketUser != "" &&
		l.SocketGroup != "" {
		uConfig = &listenerutil.UnixSocketsConfig{
			Mode:  l.SocketMode,
			User:  l.SocketUser,
			Group: l.SocketGroup,
		}
	}
	ln, err := listenerutil.UnixSocketListener(l.Address, uConfig)
	if err != nil {
		return "", nil, err
	}

	return l.Address, ln, nil
}

func listenerWrapProxy(ln net.Listener, l *listenerutil.ListenerConfig) (net.Listener, error) {
	behavior := l.ProxyProtocolBehavior
	if behavior == "" {
		return ln, nil
	}

	authorizedAddrs := make([]string, 0, len(l.ProxyProtocolAuthorizedAddrs))
	for _, v := range l.ProxyProtocolAuthorizedAddrs {
		authorizedAddrs = append(authorizedAddrs, v.String())
	}

	var policyFunc proxyproto.PolicyFunc

	switch behavior {
	case "use_always":
		policyFunc = func(upstream net.Addr) (proxyproto.Policy, error) {
			return proxyproto.USE, nil
		}

	case "allow_authorized":
		if len(authorizedAddrs) == 0 {
			return nil, errors.New("proxy_protocol_behavior set but no proxy_protocol_authorized_addrs value")
		}
		policyFunc = proxyproto.MustLaxWhiteListPolicy(authorizedAddrs)

	case "deny_unauthorized":
		if len(authorizedAddrs) == 0 {
			return nil, errors.New("proxy_protocol_behavior set but no proxy_protocol_authorized_addrs value")
		}
		policyFunc = proxyproto.MustStrictWhiteListPolicy(authorizedAddrs)

	default:
		return nil, fmt.Errorf("unknown %q value: %q", "proxy_protocol_behavior", behavior)
	}

	proxyListener := &proxyproto.Listener{
		Listener: ln,
		Policy:   policyFunc,
	}

	return proxyListener, nil
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

func (ln TCPKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	if err := tc.SetKeepAlive(true); err != nil {
		return nil, err
	}
	if err := tc.SetKeepAlivePeriod(3 * time.Minute); err != nil {
		return nil, err
	}
	return tc, nil
}
