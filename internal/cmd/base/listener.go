package base

import (
	// We must import sha512 so that it registers with the runtime so that
	// certificates that use it can be parsed.
	_ "crypto/sha512"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-alpnmux"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/shared-secure-libs/configutil"
	"github.com/hashicorp/shared-secure-libs/listenerutil"
	"github.com/hashicorp/shared-secure-libs/reloadutil"
	"github.com/mitchellh/cli"
	"github.com/pires/go-proxyproto"
	"google.golang.org/grpc"
)

type ServerListener struct {
	Mux          *alpnmux.ALPNMux
	Config       *configutil.Listener
	HTTPServer   *http.Server
	GrpcServer   *grpc.Server
	ALPNListener net.Listener
}

type WorkerAuthInfo struct {
	CACertPEM       []byte `json:"ca_cert"`
	CertPEM         []byte `json:"cert"`
	KeyPEM          []byte `json:"key"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	ConnectionNonce string `json:"connection_nonce"`
}

// Factory is the factory function to create a listener.
type ListenerFactory func(*configutil.Listener, hclog.Logger, cli.Ui) (*alpnmux.ALPNMux, map[string]string, reloadutil.ReloadFunc, error)

// BuiltinListeners is the list of built-in listener types.
var BuiltinListeners = map[string]ListenerFactory{
	"tcp": tcpListenerFactory,
}

// New creates a new listener of the given type with the given
// configuration. The type is looked up in the BuiltinListeners map.
func NewListener(l *configutil.Listener, logger hclog.Logger, ui cli.Ui) (*alpnmux.ALPNMux, map[string]string, reloadutil.ReloadFunc, error) {
	f, ok := BuiltinListeners[l.Type]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown listener type: %q", l.Type)
	}

	return f(l, logger, ui)
}

func tcpListenerFactory(l *configutil.Listener, logger hclog.Logger, ui cli.Ui) (*alpnmux.ALPNMux, map[string]string, reloadutil.ReloadFunc, error) {
	if l.Address == "" {
		if len(l.Purpose) == 1 {
			switch l.Purpose[0] {
			case "cluster":
				l.Address = "127.0.0.1:9201"
			case "proxy":
				l.Address = "127.0.0.1:9202"
			default:
				l.Address = "127.0.0.1:9200"
			}
		}
	}

	bindProto := "tcp"

	// If they've passed 0.0.0.0, we only want to bind on IPv4
	// rather than golang's dual stack default
	if strings.HasPrefix(l.Address, "0.0.0.0:") {
		bindProto = "tcp4"
	}

	if l.RandomPort {
		colon := strings.Index(l.Address, ":")
		if colon != -1 {
			// colon+1 because it needs to end in a colon to be automatically
			// assigned by Go
			l.Address = l.Address[0 : colon+1]
		}
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

	if _, ok := os.LookupEnv("BOUNDARY_LOG_CONNECTION_MUXING"); !ok {
		logger = nil
	}
	alpnMux := alpnmux.New(ln, logger)

	if l.TLSDisable {
		return alpnMux, props, nil, nil
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

func listenerWrapProxy(ln net.Listener, l *configutil.Listener) (net.Listener, error) {
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
