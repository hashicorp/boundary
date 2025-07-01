// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package dawdle provides a simple proxy for testing network
// connections, offering various facilities to introduce unfavorable
// network conditions.
//
// As the package is designed for use in testing, a large amount of
// functionality is exported. It's recommended that you use the most
// amount of composition that makes sense for you, with the intention
// being that if you need access the more lower-level parts of the
// package, they are available to you.
package dawdle

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

const defaultBufferSize = 32 * 1024

// ErrNewProxy denotes an error in proxy creation.
func ErrNewProxy(err error) error {
	return fmt.Errorf("error creating proxy: %w", err)
}

// ErrProxyListener denotes an error starting the proxy listener.
func ErrProxyListener(err error) error {
	return fmt.Errorf("error starting listener: %w", err)
}

// ErrProxyRun denotes an error running the proxy.
func ErrProxyRun(err error) error {
	return fmt.Errorf("error running proxy: %w", err)
}

// ErrProxyHandleRemoteConnect denotes an error making the connection
// to the remote.
func ErrProxyHandleRemoteConnect(err error) error {
	return fmt.Errorf("error connecting to remote: %w", err)
}

// ErrProxyHandleStream denotes an error reading the connection.
func ErrProxyHandleStream(err error) error {
	return fmt.Errorf("error in network stream: %w", err)
}

// ErrProxyHandleStream denotes an error reading the connection.
func ErrProxyHandleCloseListener(err error) error {
	return fmt.Errorf("error closing listener: %w", err)
}

// ErrProxyClose denotes an error on general close. Errors are not
// wrapped.
func ErrProxyClose(errs []error) error {
	b := new(strings.Builder)
	for _, e := range errs {
		b.WriteString(e.Error())
		b.WriteRune('\n')
	}

	return errors.New(b.String())
}

// ErrProxyCloseListener denotes an error closing the listener.
func ErrProxyCloseListener(err error) error {
	return fmt.Errorf("error closing listener: %w", err)
}

// ErrProxyCloseConnections denotes an error closing the listener.
// Individual errors are not wrapped.
func ErrProxyCloseConnections(errs []error) error {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}

	return fmt.Errorf("error closing connections:\n\t%s", strings.Join(msgs, "\n\t"))
}

// ProxyOption are options designed to control the behavior of the
// proxy.
type ProxyOption func(p *proxy) error

// WithRbufSize supplies the read buffer size for proxied
// connections. A size of less than 1 means the default size will be
// used (32k).
func WithRbufSize(size int) func(p *proxy) error {
	return func(p *proxy) error {
		if size < 1 {
			size = defaultBufferSize
		}

		p.rbufSize = size
		return nil
	}
}

// WithWbufSize supplies the write buffer size for proxied
// connections. A size of less than 1 means the default size will be
// used (32k).
func WithWbufSize(size int) func(p *proxy) error {
	return func(p *proxy) error {
		if size < 1 {
			size = defaultBufferSize
		}

		p.wbufSize = size
		return nil
	}
}

// WithLogger sets a log for writing deep errors and other debugging
// data to.
func WithLogger(logger *log.Logger) func(p *proxy) error {
	return func(p *proxy) error {
		p.logger = logger
		return nil
	}
}

// WithListener allows an existing listener to be passed in as the
// local connection.
//
// Note that if this is passed in, localAddr in NewProxy is ignored,
// and the server is started immediately.
//
// The protocol of the listener needs to match the protocol passed
// into NewProxy. Only TCP listeners are allowed.
func WithListener(ln net.Listener) func(p *proxy) error {
	return func(p *proxy) error {
		switch ln.(type) {
		case *net.TCPListener:
			if p.proto != "tcp" {
				return fmt.Errorf("listener type mismatch: TCP listener for %s proto", p.proto)
			}

		default:
			return fmt.Errorf("unsupported listener protocol %s", ln.Addr().Network())
		}

		p.ln = ln
		return nil
	}
}

// Proxy represents a proxy server.
type proxy struct {
	proto              string
	localAddr          string
	remoteAddr         string
	ln                 net.Listener
	conns              *connMap
	rbufSize, wbufSize int
	pauseCh            chan struct{}
	pauseChMutex       *sync.RWMutex
	logger             *log.Logger
}

type connMap struct {
	*sync.RWMutex
	m map[string]net.Conn
}

func newConnMap() *connMap {
	return &connMap{
		RWMutex: new(sync.RWMutex),
		m:       make(map[string]net.Conn),
	}
}

func (m *connMap) Store(c net.Conn) {
	m.Lock()
	defer m.Unlock()
	m.m[c.RemoteAddr().String()] = c
}

func (m *connMap) Delete(c net.Conn) {
	m.Lock()
	defer m.Unlock()
	delete(m.m, c.RemoteAddr().String())
}

// CloseAll closes and deletes all existing connections in the
// connMap. A single lock is held for the duration.
//
// Connections are deleted regardless of whether or not there is an
// error.
func (m *connMap) CloseAll() []error {
	m.Lock()
	defer m.Unlock()
	var errs []error
	for _, c := range m.m {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}

		delete(m.m, c.RemoteAddr().String())
	}

	return errs
}

// NewProxy creates the proxy, connecting localAddr with remoteAddr.
//
// Currently the only protocol supported is "tcp".
func NewProxy(proto, localAddr, remoteAddr string, opts ...ProxyOption) (*proxy, error) {
	// Validate remoteAddr so that we won't run into errors using it
	// later.
	switch proto {
	case "tcp":
		if _, err := net.ResolveTCPAddr(proto, remoteAddr); err != nil {
			return nil, ErrNewProxy(err)
		}

	default:
		return nil, ErrNewProxy(fmt.Errorf("unsupported protocol %s", proto))
	}

	p := &proxy{
		proto:      proto,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		conns:      newConnMap(),
		rbufSize:   defaultBufferSize,
		wbufSize:   defaultBufferSize,
		pauseCh: func() chan struct{} {
			c := make(chan struct{})
			close(c)
			return c
		}(),
		pauseChMutex: new(sync.RWMutex),
	}

	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, ErrNewProxy(err)
		}
	}

	if p.ln != nil {
		go func() {
			err := p.run()
			p.log(err.Error())
		}()
	}

	return p, nil
}

// ListenerAddr gives the address of the listener. If the listener
// has not been started yet, it returns empty.
func (p *proxy) ListenerAddr() string {
	if p.ln == nil {
		return ""
	}

	return p.ln.Addr().String()
}

// Start starts the server and returns immediately, as long as the
// listener can be started.
func (p *proxy) Start() error {
	if err := p.startListener(); err != nil {
		return err
	}

	go func() {
		err := p.run()
		p.log(err.Error())
	}()

	return nil
}

// Run starts the listener, runs the main accept loop, and hands off
// to proxy handlers.
//
// Run blocks until it's done and returns any error from the last
// Accept() on the listener. Use Start() instead if you do not want
// control over this process and would rather just return
// immediately.
func (p *proxy) Run() error {
	if err := p.startListener(); err != nil {
		return err
	}

	return p.run()
}

// Close shuts down the listener and all connections.
func (p *proxy) Close() error {
	var errs []error
	if err := p.CloseListener(); err != nil {
		errs = append(errs, err)
	}

	if err := p.CloseConnections(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return ErrProxyClose(errs)
	}

	return nil
}

// CloseListener shuts down the listener. It does not shut down any
// existing connections.
func (p *proxy) CloseListener() error {
	if p.ln != nil {
		if err := p.ln.Close(); err != nil {
			return ErrProxyCloseListener(err)
		}
	}

	return nil
}

// CloseConnections shuts down all existing connections. It does not
// shut down the listener.
func (p *proxy) CloseConnections() error {
	errs := p.conns.CloseAll()
	if len(errs) > 0 {
		return ErrProxyCloseConnections(errs)
	}

	return nil
}

// Pause re-initializes the internal pause channel and leaves it
// open.
//
// This causes all any and all handlers to stop what they are doing:
// sending and receiving is paused after the most recent copy is
// done, and new connections are blocked after connecting.
//
// Note that any copies that are currently blocked will complete
// before pausing. Consider turning buffers down if you are having
// trouble pausing mid-stream.
//
// Note that it's unsupported and undefined right now to call pause
// twice in a row - this will likely cause some connections to block
// forever and be un-resumable. This will be fixed in later versions.
func (p *proxy) Pause() {
	p.pauseChMutex.Lock()
	p.pauseCh = make(chan struct{})
	p.pauseChMutex.Unlock()
}

// Resume resumes any blocked connections by closing the internal
// pause channel. After this, Pause must be called again to pause
// connections.
//
// Note that calling Resume without pausing the proxy first, or
// calling resume consecutively, will cause a panic.
func (p *proxy) Resume() {
	p.pauseChMutex.Lock()
	close(p.pauseCh)
	p.pauseChMutex.Unlock()
}

func (p *proxy) run() error {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return ErrProxyRun(err)
		}

		p.conns.Store(conn)
		go func() {
			err := p.Handle(conn)
			p.log(err.Error())
			p.conns.Delete(conn)
		}()
	}
}

// Handle is the general read-write handler for the connection.
//
// Handle handles connection with and the general read/write loops
// with the remote host.
func (p *proxy) Handle(local net.Conn) error {
	defer local.Close()

	// Connect to remote
	remote, err := net.Dial(p.proto, p.remoteAddr)
	if err != nil {
		return ErrProxyHandleRemoteConnect(err)
	}

	defer remote.Close()

	errCh := make(chan error)

	go func() {
		for {
			p.pauseChMutex.RLock()
			pauseCh := p.pauseCh
			p.pauseChMutex.RUnlock()
			<-pauseCh
			if _, err := io.CopyN(remote, local, int64(p.rbufSize)); err != nil {
				errCh <- err
				break
			}
		}
	}()

	go func() {
		for {
			p.pauseChMutex.RLock()
			pauseCh := p.pauseCh
			p.pauseChMutex.RUnlock()
			<-pauseCh
			if _, err := io.CopyN(local, remote, int64(p.wbufSize)); err != nil {
				errCh <- err
				break
			}
		}
	}()

	err = <-errCh
	return ErrProxyHandleStream(err)
}

// startListener starts the listener.
func (p *proxy) startListener() error {
	if p.ln != nil {
		return ErrProxyListener(errors.New("listener already started"))
	}

	var err error
	p.ln, err = net.Listen(p.proto, p.localAddr)
	if err != nil {
		return ErrProxyListener(err)
	}

	return nil
}

// log is an internal function that logs if a logger is present.
func (p *proxy) log(s string) {
	if p.logger != nil {
		p.logger.Println(s)
	}
}
