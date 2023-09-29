package proxy

import (
	"errors"
	"net/netip"
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
	WithListenAddr        netip.AddrPort
	WithConnectionsLeftCh chan int32
	WithWorkerHost        *string
}

// Option is a function that takes in an options struct and sets values or
// returns an error
type Option func(*Options) error

func getDefaultOptions() *Options {
	return &Options{
		WithListenAddr: netip.MustParseAddrPort("127.0.0.1:0"),
	}
}

// WithListenAddr allows overriding an address to listen on. It is _not_ an
// error to pass an invalid netip.AddrPort, e.g. from an allocated but unset
// AddrPort; this will simply cause it to use the default.
func WithListenAddr(with netip.AddrPort) Option {
	return func(o *Options) error {
		if with.IsValid() {
			o.WithListenAddr = with
		}
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
// authorization data. This is mostly useful for tests.
func WithWorkerHost(with string) Option {
	return func(o *Options) error {
		o.WithWorkerHost = new(string)
		*o.WithWorkerHost = with
		return nil
	}
}
