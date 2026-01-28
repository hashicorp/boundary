// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
)

// getOpts iterates the inbound Options and returns a struct and any errors
func getOpts(opt ...Option) (*Options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(opts); err != nil {
			return nil, err
		}

	}
	return opts, nil
}

// Options contains various options. The values are exported since the options
// are parsed in various other packages.
type Options struct {
	WithListener                 net.Listener
	WithListenAddrPort           netip.AddrPort
	WithConnectionsLeftCh        chan int32
	WithWorkerHost               string
	WithSessionAuthorizationData *targets.SessionAuthorizationData
	WithSkipSessionTeardown      bool
	withSessionTeardownTimeout   time.Duration
	withApiClient                *api.Client
	withInactivityTimeout        time.Duration
}

// Option is a function that takes in an options struct and sets values or
// returns an error
type Option func(*Options) error

func getDefaultOptions() *Options {
	return &Options{
		WithListenAddrPort: netip.MustParseAddrPort("127.0.0.1:0"),
	}
}

// WithListener allows passing a listener on which to accept connections. If
// this and WithListenAddrPort are both specified, this will take precedence.
func WithListener(with net.Listener) Option {
	return func(o *Options) error {
		if with == nil {
			return errors.New("nil listener passed to WithListener")
		}
		o.WithListener = with
		return nil
	}
}

// WithListenAddrPort allows overriding an address to listen on. Mutually
// exclusive with WithListener; that option will take precedence. If you do not
// want a TCP connection you must use WithListener.
func WithListenAddrPort(with netip.AddrPort) Option {
	return func(o *Options) error {
		if !with.IsValid() {
			return errors.New("invalid addr/port passed to WithListenAddrPort")
		}
		o.WithListenAddrPort = with
		return nil
	}
}

// WithConnectionsLeftCh allows providing a channel to receive updates about how
// many connections are left. It is the caller's responsibility to ensure that
// this is drained and does not block.
func WithConnectionsLeftCh(with chan int32) Option {
	return func(o *Options) error {
		if with == nil {
			return errors.New("channel passed to WithConnectionsLeftCh is nil")
		}
		o.WithConnectionsLeftCh = with
		return nil
	}
}

// WithWorkerHost can be used to override the worker host read from the session
// authorization data. This can be used to override the SNI value in the client
// TLS configuration and is mostly useful for tests.
func WithWorkerHost(with string) Option {
	return func(o *Options) error {
		o.WithWorkerHost = with
		return nil
	}
}

// WithSessionAuthorizationData can be used to provide already-unmarshaled
// session authorization instead of a string token.
func WithSessionAuthorizationData(with *targets.SessionAuthorizationData) Option {
	return func(o *Options) error {
		if with == nil {
			return errors.New("data passed to WithSessionAuthorizationData is nil")
		}
		o.WithSessionAuthorizationData = with
		return nil
	}
}

// WithSkipSessionTeardown can be used to override the normal behavior of the
// session sending a teardown request to the worker on completion. This is
// useful if you know that this will result in an error (for instance, if the
// worker is going to be offline) and want to avoid the attempted connection or
// avoid the error rather than ignore it.
func WithSkipSessionTeardown(with bool) Option {
	return func(o *Options) error {
		o.WithSkipSessionTeardown = with
		return nil
	}
}

// WithSessionTeardownTimeout provides an optional duration which overwrites
// the default session teardown timeout.
func WithSessionTeardownTimeout(with time.Duration) Option {
	return func(o *Options) error {
		o.withSessionTeardownTimeout = with
		return nil
	}
}

// WithApiClient provides an optional Boundary API client
// Experimental: It is unclear whether the current usage of this option is the
// approach that we want to take in the long term. This may be removed at any
// point going forward.
func WithApiClient(with *api.Client) Option {
	return func(o *Options) error {
		o.withApiClient = with
		return nil
	}
}

// WithInactivityTimeout provides an optional duration after which a session
// with no active connections will be cancelled
func WithInactivityTimeout(with time.Duration) Option {
	return func(o *Options) error {
		o.withInactivityTimeout = with
		return nil
	}
}
