// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"crypto/rand"
	"io"
	"net"

	serverpb "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/crypto/ssh"
)

// Option - how Options are passed as arguments.
type Option func(*Options)

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Options = how options are represented
type Options struct {
	WithInjectedApplicationCredentials []*serverpb.Credential
	WithPostConnectionHook             func(net.Conn)
	WithDnsServerAddress               string
	WithTestKdcAddress                 string
	WithTestKerberosServerHostname     string
	WithLogger                         hclog.Logger
	WithSshHostKeyCallback             ssh.HostKeyCallback
	WithRandomReader                   io.Reader
}

func getDefaultOptions() Options {
	return Options{
		WithInjectedApplicationCredentials: nil,
		WithPostConnectionHook:             nil,
		WithLogger:                         hclog.NewNullLogger(),
		WithRandomReader:                   rand.Reader,
	}
}

// WithInjectedApplicationCredentials provides an optional injected application
// credentials to use when establishing a proxy
func WithInjectedApplicationCredentials(creds []*serverpb.Credential) Option {
	return func(o *Options) {
		o.WithInjectedApplicationCredentials = creds
	}
}

// WithPostConnectionHook provides a hook function to be called after a
// connection is established in a dialFunction.  When a dialer accepts
// WithPostConnectionHook the passed in function should be called prior to any
// other blocking call.
func WithPostConnectionHook(fn func(net.Conn)) Option {
	return func(o *Options) {
		o.WithPostConnectionHook = fn
	}
}

// WithDnsServerAddress allows specifying lookup of the endpoint to happen via
// an alternate DNS server. Must be in scheme://host:port form where scheme is
// "udp" or "tcp".
func WithDnsServerAddress(with string) Option {
	return func(o *Options) {
		o.WithDnsServerAddress = with
	}
}

// WithTestKdcAddress allows specifying a test KDC address to use for testing
func WithTestKdcAddress(with string) Option {
	return func(o *Options) {
		o.WithTestKdcAddress = with
	}
}

// WithTestKerberosServerHostname allows specifying a test Kerberos server
func WithTestKerberosServerHostname(with string) Option {
	return func(o *Options) {
		o.WithTestKerberosServerHostname = with
	}
}

// WithLogger allows specifying a logger to be used during session proxy
func WithLogger(l hclog.Logger) Option {
	return func(o *Options) {
		o.WithLogger = l
	}
}

// WithSshHostKeyCallback allows specifying a ssh.HostKeyCallback function
// to be used for host key verification.
func WithSshHostKeyCallback(with ssh.HostKeyCallback) Option {
	return func(o *Options) {
		o.WithSshHostKeyCallback = with
	}
}

// WithRandomReader provides an option to specify a random reader.
func WithRandomReader(reader io.Reader) Option {
	return func(o *Options) {
		o.WithRandomReader = reader
	}
}
