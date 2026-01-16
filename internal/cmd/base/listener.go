// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	"crypto/tls"

	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/mitchellh/cli"
	"github.com/pires/go-proxyproto"
	"google.golang.org/grpc"
)

type ServerListener struct {
	Config          *listenerutil.ListenerConfig
	HTTPServer      *http.Server
	GrpcServer      *grpc.Server
	ApiListener     net.Listener
	ClusterListener net.Listener
	ProxyListener   net.Listener
	OpsListener     net.Listener
}

type WorkerAuthInfo struct {
	CertPEM         []byte `json:"cert"`
	KeyPEM          []byte `json:"key"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	ConnectionNonce string `json:"connection_nonce"`
	ProxyAddress    string `json:"proxy_address"`
	BoundaryVersion string `json:"boundary_version"`
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
func NewListener(l *listenerutil.ListenerConfig, ui cli.Ui) (net.Listener, map[string]string, reloadutil.ReloadFunc, error) {
	f, ok := BuiltinListeners[l.Type]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown listener type: %q", l.Type)
	}

	if len(l.Purpose) != 1 {
		return nil, nil, nil, fmt.Errorf("expected single listener purpose, found %d", len(l.Purpose))
	}
	purpose := l.Purpose[0]

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

	switch purpose {
	case "cluster":
		// We handle our own cluster authentication
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

	if l.TLSDisable {
		return ln, props, nil, nil
	}

	if l.TLSCertFile == "" {
		return nil, nil, nil, fmt.Errorf("tls not disabled for listener at address %q with purpose %q but no certificate file supplied", finalAddr, purpose)
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

	return tls.NewListener(ln, tlsConfig), props, reloadFunc, nil
}

func tcpListenerFactory(purpose string, l *listenerutil.ListenerConfig, ui cli.Ui) (string, net.Listener, error) {
	if l.Address == "" {
		switch purpose {
		case "api":
			l.Address = "127.0.0.1:9200"
		case "cluster":
			l.Address = "127.0.0.1:9201"
		case "proxy":
			l.Address = "127.0.0.1:9202"
		case "ops":
			l.Address = "127.0.0.1:9203"
		default:
			return "", nil, errors.New("no purpose provided for listener and no address given")
		}
	}

	host, port, err := util.SplitHostPort(l.Address)
	if err != nil && !errors.Is(err, util.ErrMissingPort) {
		return "", nil, fmt.Errorf("error splitting host/port: %w", err)
	}
	if port == "" {
		switch purpose {
		case "api":
			port = "9200"
		case "cluster":
			port = "9201"
		case "proxy":
			port = "9202"
		case "ops":
			port = "9203"
		default:
			return "", nil, errors.New("no purpose provided for listener and no port discoverable")
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
		port = "0" // net.Listen will choose an available port automatically. Used for tests.
	}

	finalListenAddr := net.JoinHostPort(host, port)
	normalizedListenAddr, err := parseutil.NormalizeAddr(finalListenAddr)
	if err != nil {
		return "", nil, fmt.Errorf("failed to normalize final listen addr %q: %w", finalListenAddr, err)
	}
	finalListenAddr = normalizedListenAddr

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
