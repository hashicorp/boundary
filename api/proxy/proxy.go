// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/go-secure-stdlib/temperror"
	ua "go.uber.org/atomic"
)

// Note: Much of the proxying behavior is tested in various tests within
// internal/tests but those cannot be included in this package as they would
// create a dependency on the main module from this module.

// This can take more time than you might expect, especially if a lot of these
// are sent at once, so the timeout is quite long. We could allow a custom
// timeout to be an option if we wish.
const sessionCancelTimeout = 30 * time.Second

type ClientProxy struct {
	tofuToken             string
	cachedListenerAddress *ua.String
	connectionsLeft       *atomic.Int32
	activeConns           *atomic.Int32
	connsLeftCh           chan int32
	callerConnsLeftCh     chan int32
	apiClient             *api.Client
	sessionAuthzData      *targets.SessionAuthorizationData
	createTime            time.Time
	expiration            time.Time
	ctx                   context.Context
	cancel                context.CancelFunc
	transport             *http.Transport
	workerAddr            string
	listenAddrPort        netip.AddrPort
	listener              *atomic.Value
	listenerCloseOnce     *sync.Once
	clientTlsConf         *tls.Config
	connWg                *sync.WaitGroup
	started               *atomic.Bool
	skipSessionTeardown   bool
	closeReason           *atomic.Value
}

// New creates a new client proxy. The given context should be cancelable; once
// the proxy is started, cancel the context to stop the proxy. The proxy may
// also cancel on its own if the session expires or there are no connections
// left.
//
// Supported options:
//
// * WithListenAddrPort - Specify a TCP address and port on which to listen
//
// * WithListener - Specify a custom listener on which to accept connections;
// overrides WithListenAddrPort if both are set
//
// * WithSessionAuthorizationData - Specify an already-unmarshaled session
// authorization object. If set, authzToken can be empty.
//
// * WithConnectionsLeftCh - Specify a channel on which to send the number of
// remaining connections as they are consumed
//
// * WithWorkerHost - If set, use this host name as the SNI host when making the
// TLS connection to the worker
//
// EXPERIMENTAL: While this API is not expected to change, it is new and
// feedback from users may necessitate changes.
func New(ctx context.Context, authzToken string, opt ...Option) (*ClientProxy, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("could not parse options: %w", err)
	}

	if authzToken == "" && opts.WithSessionAuthorizationData == nil {
		return nil, fmt.Errorf("empty session authorization token and object")
	}

	p := &ClientProxy{
		cachedListenerAddress: ua.NewString(""),
		connsLeftCh:           make(chan int32),
		connectionsLeft:       new(atomic.Int32),
		activeConns:           new(atomic.Int32),
		listener:              new(atomic.Value),
		listenerCloseOnce:     new(sync.Once),
		connWg:                new(sync.WaitGroup),
		listenAddrPort:        opts.WithListenAddrPort,
		callerConnsLeftCh:     opts.WithConnectionsLeftCh,
		started:               new(atomic.Bool),
		skipSessionTeardown:   opts.WithSkipSessionTeardown,
		apiClient:             opts.withApiClient,
		closeReason:           new(atomic.Value),
	}

	if opts.WithListener != nil {
		p.listener.Store(opts.WithListener)
	}

	p.tofuToken, err = base62.Random(20)
	if err != nil {
		return nil, fmt.Errorf("could not derive random bytes for tofu token: %w", err)
	}

	p.sessionAuthzData = opts.WithSessionAuthorizationData
	if p.sessionAuthzData == nil {
		p.sessionAuthzData, err = targets.SessionAuthorization{AuthorizationToken: authzToken}.GetSessionAuthorizationData()
		if err != nil {
			return nil, fmt.Errorf("error turning authz token into authorization data: %w", err)
		}
	}

	if len(p.sessionAuthzData.WorkerInfo) == 0 {
		return nil, errors.New("no workers found in authorization data")
	}

	if opts.WithListener == nil {
		if p.listenAddrPort.Port() == 0 {
			p.listenAddrPort = netip.AddrPortFrom(p.listenAddrPort.Addr(), uint16(p.sessionAuthzData.DefaultClientPort))
		}
	}
	p.connectionsLeft.Store(p.sessionAuthzData.ConnectionLimit)
	p.workerAddr = p.sessionAuthzData.WorkerInfo[0].Address

	tlsConf, err := p.clientTlsConfig(opt...)
	if err != nil {
		return nil, fmt.Errorf("error creating TLS configuration: %w", err)
	}
	p.createTime = p.sessionAuthzData.CreatedTime
	p.expiration = p.sessionAuthzData.Expiration

	// We don't _rely_ on client-side timeout verification but this prevents us
	// seeming to be ready for a connection that will immediately fail when we
	// try to actually make it
	p.ctx, p.cancel = context.WithDeadlineCause(ctx, p.expiration, fmt.Errorf("Session has expired"))

	transport := cleanhttp.DefaultTransport()
	transport.DisableKeepAlives = false
	// This isn't/shouldn't be used anyways really because the connection is
	// hijacked, just setting for completeness
	transport.IdleConnTimeout = 0
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &tls.Dialer{Config: tlsConf}
		return dialer.DialContext(ctx, network, addr)
	}
	p.transport = transport

	return p, nil
}

// Start starts the listener for client proxying. It ends, with any errors, when
// the listener is closed and no connections are left. Cancel the client's proxy
// to force this to happen early. It is not safe to call Start twice, including
// once it has exited, and will immediately error in this case; create a new
// ClientProxy with New().
//
// Note: if a custom listener implementation is used and the implementation can
// return a Temporary error, the listener will not be closed on that condition
// and no feedback will be given. It is up to the listener implementation to
// inform the client, if needed, of any status causing a Temporary error to be
// returned on accept.
//
// EXPERIMENTAL: While this API is not expected to change, it is new and
// feedback from users may necessitate changes.
func (p *ClientProxy) Start(opt ...Option) (retErr error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return fmt.Errorf("could not parse options: %w", err)
	}
	if !p.started.CompareAndSwap(false, true) {
		return errors.New("proxy was already started")
	}

	defer p.cancel()

	if opts.withSessionTeardownTimeout == 0 {
		opts.withSessionTeardownTimeout = sessionCancelTimeout
	}

	if p.listener.Load() == nil {
		var err error
		ln, err := net.ListenTCP("tcp", &net.TCPAddr{
			IP:   p.listenAddrPort.Addr().AsSlice(),
			Port: int(p.listenAddrPort.Port()),
		})
		if err != nil {
			return fmt.Errorf("unable to start listening: %w", err)
		}
		p.listener.Store(ln)
	}

	listenerCloseFunc := func() {
		p.listenerCloseOnce.Do(func() {
			// Forces the for loop to exit instead of spinning on errors
			p.connectionsLeft.Store(0)
			if err := p.listener.Load().(net.Listener).Close(); err != nil && err != net.ErrClosed {
				retErr = errors.Join(retErr, fmt.Errorf("error closing proxy listener: %w", err))
			}
		})
	}

	// Ensure closing the listener runs on any other return condition
	defer listenerCloseFunc()

	var proxyAutoClose *time.Timer
	if opts.withInactivityTimeout > 0 {
		// automatically close the proxy when inactive
		proxyAutoClose = time.AfterFunc(opts.withInactivityTimeout, func() {
			p.cancel()
			p.setCloseReason("Inactivity timeout reached")
		})
		// Stop timer until we have at least one connection, then reset/stop based on activity
		proxyAutoClose.Stop()
	}

	activeConnCh := make(chan int32)
	activeConnFn := func(d int32) {
		activeConnCh <- p.activeConns.Add(d)
	}

	fin := make(chan error, 10)
	p.connWg.Add(1)
	go func() {
		defer p.connWg.Done()
		for {
			listeningConn, err := p.listener.Load().(net.Listener).Accept()
			if err != nil {
				select {
				case <-p.ctx.Done():
					return
				default:
					if errors.Is(err, net.ErrClosed) {
						// Generally this will be because we canceled the
						// context or ran out of session connections and are
						// winding down. This will never revert, so return.
						return
					}
					// If the upstream listener indicates that this is an error
					// with e.g. just this connection, don't close, just
					// continue
					if temperror.IsTempError(err) {
						continue
					}
					// No reason to think we can successfully handle the next
					// connection that comes our way, so cancel the proxy
					fin <- fmt.Errorf("error from accept: %w", err)
					listenerCloseFunc()
					p.cancel()
					return
				}
			}
			activeConnFn(1)
			p.connWg.Add(1)
			go func() {
				defer activeConnFn(-1)
				defer listeningConn.Close()
				defer p.connWg.Done()
				wsConn, err := p.getWsConn(p.ctx)
				if err != nil {
					fin <- fmt.Errorf("error from getWsConn: %w", err)
					// No reason to think we can successfully handle the next
					// connection that comes our way, so cancel the proxy
					listenerCloseFunc()
					p.cancel()
					return
				}
				if err := p.runTcpProxyV1(wsConn, listeningConn); err != nil {
					fin <- fmt.Errorf("error from runTcpProxyV1: %w", err)
					// No reason to think we can successfully handle the next
					// connection that comes our way, so cancel the proxy
					listenerCloseFunc()
					p.cancel()
					return
				}

				// TODO: Determine if this is useful or if there is a better approach
				// that we may use in the long term.
				if p.apiClient != nil {
					// If we can tell that the session for the connection we just
					// closed is terminated, we can close the listener, otherwise
					// might as well leave it open so the next connection can be
					// tried.
					sess, err := sessions.NewClient(p.apiClient).Read(p.ctx, p.sessionAuthzData.SessionId)
					if err != nil || sess == nil || sess.Item == nil || sess.Item.Status == "active" {
						return
					}

					// We got a valid session response for the session we just
					// closed a connection for. Since the status isn't active
					// we can treat the session as no longer being able to
					// support connections, so close this proxy.
					fin <- fmt.Errorf("session no longer active")
					listenerCloseFunc()
					p.cancel()
				}
			}()
		}
	}()

	p.connWg.Add(1)
	go func() {
		defer func() {
			// Run a function (last, after connwg is done) just to ensure that
			// we drain from this in case any connections starting as this
			// number changes are trying to send the information down
			for {
				select {
				case <-p.connsLeftCh:
				default:
					return
				}
			}
		}()
		defer p.connWg.Done()
		defer listenerCloseFunc()
		for {
			select {
			case <-p.ctx.Done():
				if err := context.Cause(p.ctx); !errors.Is(err, context.Canceled) {
					p.setCloseReason(err.Error())
				}
				return
			case connsLeft := <-p.connsLeftCh:
				p.connectionsLeft.Store(connsLeft)
				if p.callerConnsLeftCh != nil {
					p.callerConnsLeftCh <- connsLeft
				}
				if connsLeft == 0 {
					// Close the listener as we can't authorize any more
					// connections
					p.setCloseReason("No connections left in session")
					return
				}
			case activeConns := <-activeConnCh:
				switch {
				case proxyAutoClose == nil:
					//  do nothing if timer is not set
				case opts.withInactivityTimeout <= 0:
					// no timeout was set, timer should not be reset for inactivity
					// this should never happen due to the proxyAutoClose nil check above, but just in case
				case activeConns > 0:
					// stop timer when we have a new conneciton
					proxyAutoClose.Stop()
				case activeConns == 0:
					// reset timer when we have no more active connections
					proxyAutoClose.Reset(opts.withInactivityTimeout)
				}
			}
		}
	}()

	p.connWg.Wait()

	{
		// the go funcs are done, so we can safely close the chan and range over any errors
		close(fin)
		var finErrors []error
		for err := range fin {
			finErrors = append(finErrors, err)
		}
		if len(finErrors) > 0 {
			return errors.Join(finErrors...)
		}
	}

	var sendSessionCancel bool
	// If we're not after expiration, ensure there is a bit of buffer in
	// case clocks are not quite the same between worker and this machine
	if time.Now().Before(p.expiration.Add(-5 * time.Minute)) {
		sendSessionCancel = true
	}

	if !sendSessionCancel || p.skipSessionTeardown {
		return nil
	}

	return p.CloseSession(opts.withSessionTeardownTimeout)
}

// CloseSession attempts to close the currently proxied session by sending a
// request to do so to the worker proxying the connection
func (p *ClientProxy) CloseSession(sessionTeardownTimeout time.Duration) error {
	if sessionTeardownTimeout == 0 {
		sessionTeardownTimeout = sessionCancelTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionTeardownTimeout)
	defer cancel()
	if err := p.sendSessionTeardown(ctx); err != nil {
		return fmt.Errorf("error sending session teardown request to worker: %w", err)
	}
	return nil
}

// CloseReason returns the reason why the proxy was closed, if the proxy closed
// itself. If the proxy is still running or the proxy was closed externally, an
// empty string is returned.
func (p *ClientProxy) CloseReason() string {
	switch r := p.closeReason.Load().(type) {
	case string:
		return r
	default:
		return ""
	}
}

// setCloseReason updates the reason the proxy closed from an empty string to the
// provided string. setCloseReason only accepts the first provided reason for
// closing, all other calls are ignored.
func (p *ClientProxy) setCloseReason(reason string) {
	p.closeReason.CompareAndSwap(nil, reason)
}

// ListenerAddress returns the address of the client proxy listener. Because the
// listener is started with Start(), this could be called before listening
// occurs. To avoid returning until we have a valid value, pass a context;
// canceling the context will cause the function to return an empty AddrPort if
// it's not yet known. Otherwise the function will return when the address is
// available. In either case, test the result to ensure it's not empty.
//
// Warning: a non-cancelable context will cause this call to block forever until
// the listener's address can be determined.
//
// EXPERIMENTAL: While this API is not expected to change, it is new and
// feedback from users may necessitate changes.
func (p *ClientProxy) ListenerAddress(ctx context.Context) string {
	switch {
	case p.cachedListenerAddress.Load() != "":
		return p.cachedListenerAddress.Load()
	case p.listener.Load() != nil:
		addr := p.listener.Load().(net.Listener).Addr().String()
		p.cachedListenerAddress.Store(addr)
		return addr
	case ctx == nil:
		return ""
	}
	timer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			timer.Stop()
			return ""
		case <-timer.C:
			if p.listener.Load() != nil {
				timer.Stop()
				addr := p.listener.Load().(net.Listener).Addr().String()
				p.cachedListenerAddress.Store(addr)
				return addr
			}
			timer.Reset(10 * time.Millisecond)
		}
	}
}

// SessionCreatedTime returns the creation time of the session
//
// EXPERIMENTAL: While this API is not expected to change, it is new and
// feedback from users may necessitate changes.
func (p *ClientProxy) SessionCreatedTime() time.Time {
	return p.createTime
}

// SessionExpiration returns the expiration time of the session
//
// EXPERIMENTAL: While this API is not expected to change, it is new and
// feedback from users may necessitate changes.
func (p *ClientProxy) SessionExpiration() time.Time {
	return p.expiration
}

// ConnectionsLeft returns the number of connections left in the session, or -1
// if unlimited.
//
// EXPERIMENTAL: While this API is not expected to change, it is new and
// feedback from users may necessitate changes.
func (p *ClientProxy) ConnectionsLeft() int32 {
	return p.connectionsLeft.Load()
}
