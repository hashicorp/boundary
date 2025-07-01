// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	nodetls "github.com/hashicorp/nodeenrollment/tls"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/hashicorp/nodeenrollment/util/temperror"
	"google.golang.org/protobuf/types/known/structpb"
)

// ClientInfo allows us to pass information back from the TLS handshake
type ClientInfo struct {
	nextProtos  []string
	clientState *structpb.Struct
}

// InterceptingListener is a listener that transparently handles fetch
// and auth flows if the right ALPN protos are found, and passes through
// otherwise
type InterceptingListener struct {
	ctx                          context.Context
	storage                      nodeenrollment.Storage
	baseLn                       net.Listener
	baseTlsConf                  *tls.Config
	fetchCredsFn                 FetchCredsFn
	generateServerCertificatesFn GenerateServerCertificatesFn
	options                      []nodeenrollment.Option
}

// InterceptingListenerConfiguration contains config information for
// InterceptingListener
type InterceptingListenerConfiguration struct {
	// The context that will be used to call any functions once a connection is
	// accepted. Required.
	Context context.Context

	// The storage that will be used for any storage needs for connections.
	// Required.
	Storage nodeenrollment.Storage

	// The base listener to accept connections from and possibly intercept.
	// Required.
	BaseListener net.Listener

	// The TLS configuration to use if the incoming connection is not one
	// handled by this library. If nil, any connection not handled by this
	// library will result in a TLS error.
	BaseTlsConfiguration *tls.Config

	// The function to use for the FetchCredentials operation. If nil, the
	// default will be used, which is suitable for a server.
	FetchCredsFunc FetchCredsFn

	// The function to use for the GenerateServerCertificates operation. If nil,
	// the default will be used, which is suitable for a server.
	GenerateServerCertificatesFunc GenerateServerCertificatesFn

	// If provided, options to pass into various storage functions, e.g.
	// WithRandomReader, WithStorageWrapper, WithLogger, etc.
	Options []nodeenrollment.Option
}

// New creates a new listener based on the passed in listener (which should not
// be a TLS listener) and the given base TLS configuration. This function will
// substitute its own TLS configuration to handle the protos specific to
// nodeenrollment. Any connection coming in that is not using those protos will
// simply be passed through.
//
// The context value is not used here, but simply passed through to other
// library functions. To stop the listener, close it normally.
func NewInterceptingListener(
	config *InterceptingListenerConfiguration,
) (*InterceptingListener, error) {
	const op = "nodeenrollment.protocol.NewInterceptingListener"

	switch {
	case config == nil:
		return nil, fmt.Errorf("(%s) configuration is nil", op)
	case nodeenrollment.IsNil(config.Context):
		return nil, fmt.Errorf("(%s) context is nil", op)
	case nodeenrollment.IsNil(config.BaseListener):
		return nil, fmt.Errorf("(%s) base listener is nil", op)
	}

	// These functions are where we use storage, so if they are being
	// overridden, allow the provider to perform their own checks. This lets
	// some function providers not have to instantiate storage if they don't
	// need it.
	if nodeenrollment.IsNil(config.Storage) &&
		(config.FetchCredsFunc == nil || config.GenerateServerCertificatesFunc == nil) {
		return nil, fmt.Errorf("(%s) storage is nil but not all function options are non-nil", op)
	}

	l := &InterceptingListener{
		ctx:                          config.Context,
		storage:                      config.Storage,
		baseLn:                       config.BaseListener,
		baseTlsConf:                  config.BaseTlsConfiguration,
		fetchCredsFn:                 config.FetchCredsFunc,
		generateServerCertificatesFn: config.GenerateServerCertificatesFunc,
		options:                      config.Options,
	}

	if l.fetchCredsFn == nil {
		l.fetchCredsFn = func(
			ctx context.Context,
			storage nodeenrollment.Storage,
			req *types.FetchNodeCredentialsRequest,
			opt ...nodeenrollment.Option,
		) (*types.FetchNodeCredentialsResponse, error) {
			return registration.FetchNodeCredentials(ctx, storage, req, opt...)
		}
	}
	if l.generateServerCertificatesFn == nil {
		l.generateServerCertificatesFn = func(
			ctx context.Context,
			storage nodeenrollment.Storage,
			req *types.GenerateServerCertificatesRequest,
			opt ...nodeenrollment.Option,
		) (*types.GenerateServerCertificatesResponse, error) {
			return nodetls.GenerateServerCertificates(ctx, storage, req, opt...)
		}
	}

	return l, nil
}

// Accept accepts the next connection.
//
// If the TLS protos is one of our known credential fetching/auth protos, we'll
// handle it. Otherwise we pass through.
//
// You should check the resulting connection before trusting it. You can do that
// by seeing if the negotiated protocol was the auth protocol handled by this
// library:
//
//	if strings.HasPrefix(
//		returnedConn.(*protocol.Conn).Conn.ConnectionState().NegotiatedProtocol,
//		nodeenrollment.AuthenticateNodeNextProtoV1Prefix
//	) {
//		// Authenticated by this library
//	} else {
//		// Not authenticated by this library
//	}
//
// There is also some special behavior around the errors that this function
// returns. For compatibility with listeners passed into gRPC servers, most
// errors satisfy a Temporary interface so that returning an error does not
// cause the gRPC server to shut down the listener, which should really only
// happen for system-level errors rather than connection-specific errors. For
// gRPC this should likely just work, but if you need to check if this is a true
// error in your own code, you can do this:
//
//	if tempErr, ok := err.(interface {
//	  Temporary() bool
//	}); ok && tempErr.Temporary() {
//
// If it's temporary, continue on and accept the next connection.
//
// What's returned is a protocol.Conn; it contains an embedded *tls.Conn as the
// Conn variable, if needed.
//
// Supported options: WithLogger
func (l *InterceptingListener) Accept() (conn net.Conn, retErr error) {
	const op = "nodeenrollment.protocol.(InterceptingListener).Accept"
	opts, err := nodeenrollment.GetOpts(l.options...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	for {
		conn, err := l.baseLn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil, net.ErrClosed
			}
			err := fmt.Errorf("error accepting connection: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}
		if conn == nil {
			continue
		}

		// Wrap the connection in our config
		var clientInfo ClientInfo
		tlsConn := tls.Server(conn, &tls.Config{
			GetConfigForClient: l.getTlsConfigForClient(&clientInfo),
		})

		// Force a handshake to run our logic
		if err := tlsConn.HandshakeContext(l.ctx); err != nil {
			// If there is an error close the connection
			if closeErr := tlsConn.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("error closing connection: %w", closeErr))
			}
			// Return a temp error so we don't close the listener
			err := fmt.Errorf("error tls handshaking server side: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, temperror.New(fmt.Errorf("(%s) %s", op, err.Error()))
		}

		// Now that we've performed the handshake, see if it's a fetch. If so,
		// we want to close the connection and return a temp error either way so
		// that the node either retries with new creds or tries again to fetch later.
		if strings.HasPrefix(tlsConn.ConnectionState().NegotiatedProtocol, nodeenrollment.FetchNodeCredsNextProtoV1Prefix) {
			err := errors.New("fetch handled, awaiting authorization or auth connection")
			// If we got here we've already sent back the creds, so close the
			// connection and return a temp error so we keep the listener alive
			if closeErr := tlsConn.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("error closing connection: %w", closeErr))
			}
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, temperror.New(fmt.Errorf("(%s) %s", op, err.Error()))
		}

		return NewConn(tlsConn,
			nodeenrollment.WithExtraAlpnProtos(clientInfo.nextProtos),
			nodeenrollment.WithState(clientInfo.clientState),
		)
	}
}

// Addr satisfies the net.Listener interface and simply returns the base
// listener's address
func (l *InterceptingListener) Addr() net.Addr {
	return l.baseLn.Addr()
}

// Close satisfies the net.Listener interface and closes the base listener
func (l *InterceptingListener) Close() error {
	return l.baseLn.Close()
}
