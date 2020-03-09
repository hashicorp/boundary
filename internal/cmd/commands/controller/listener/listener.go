package listener

import (
	"errors"
	"io"

	"github.com/pires/go-proxyproto"

	// We must import sha512 so that it registers with the runtime so that
	// certificates that use it can be parsed.
	_ "crypto/sha512"
	"fmt"
	"net"

	"github.com/hashicorp/go-alpnmux"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/internalshared/reloadutil"
	"github.com/mitchellh/cli"
)

// Factory is the factory function to create a listener.
type Factory func(*configutil.Listener, io.Writer, cli.Ui) (*alpnmux.ALPNMux, map[string]string, reloadutil.ReloadFunc, error)

// BuiltinListeners is the list of built-in listener types.
var BuiltinListeners = map[string]Factory{
	"tcp": tcpListenerFactory,
}

// New creates a new listener of the given type with the given
// configuration. The type is looked up in the BuiltinListeners map.
func New(l *configutil.Listener, w io.Writer, ui cli.Ui) (*alpnmux.ALPNMux, map[string]string, reloadutil.ReloadFunc, error) {
	f, ok := BuiltinListeners[l.Type]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown listener type: %q", l.Type)
	}

	return f(l, w, ui)
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
