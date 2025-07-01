// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/nodeenrollment"
	nodetls "github.com/hashicorp/nodeenrollment/tls"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// Dial returns a function suitable for dialing a connection to an
// InterceptingListener. It takes in storage, an address, and options.
//
// Supported options: WithRandomReader, WithStorageWrapper (passed through to
// LoadNodeCredentials and NodeCredentials.Store),
// WithNotBeforeClockSkew/WithNotAfterClockSkew (these are used as
// NotBefore/NotAfter lifetimes for the generated cert used for client side
// TLS), WithExtraAlpnProtos (passed through to the client side TLS
// configuration),
// WithActivationToken/WithRegistrationWrapper/WithWrappingRegistrationFlowApplicationSpecificParams
// (passed through to CreateFetchNodeCredentialsRequest),
// WithLogger
func Dial(
	ctx context.Context,
	storage nodeenrollment.Storage,
	addr string,
	opt ...nodeenrollment.Option,
) (net.Conn, error) {
	const op = "nodeenrollment.protocol.Dial"

	switch {
	case nodeenrollment.IsNil(ctx):
		return nil, fmt.Errorf("(%s) nil context", op)
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nonTlsConnFn := func() (net.Conn, error) {
		dialer := &net.Dialer{}
		var err error
		var nonTlsConn net.Conn
		switch {
		case strings.HasPrefix(addr, "/"):
			nonTlsConn, err = dialer.DialContext(ctx, "unix", addr)
		default:
			nonTlsConn, err = dialer.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, fmt.Errorf("(%s) unable to dial to server: %w", op, err)
		}
		return nonTlsConn, nil
	}

	// Fetch credentials for the node
	creds, err := types.LoadNodeCredentials(ctx, storage, nodeenrollment.CurrentId, opt...)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		err := fmt.Errorf("error loading node credentials: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}
	if creds == nil {
		return nil, fmt.Errorf("(%s) loaded node credentials are nil", op)
	}

	// Add in the address to SNI for LB routing, but first ensure we're only
	// adding the host
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			host = addr
		} else {
			err := fmt.Errorf("error splitting address host/port: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}
	}
	opt = append(opt, nodeenrollment.WithServerName(host))

	if len(creds.CertificateBundles) == 0 {
		// We don't have creds yet, so attempt fetching them
		nonTlsConn, err := nonTlsConnFn()
		if err != nil {
			err := fmt.Errorf("unable to dial to server: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}

		fetchResp, err := attemptFetch(ctx, nonTlsConn, creds, opt...)
		closeErr := nonTlsConn.Close()
		if closeErr != nil {
			err = errors.Join(err, fmt.Errorf("(%s) error closing initial connection: %w", op, closeErr))
		}
		if err != nil {
			// If not authorized, this will pass ErrNotAuthorized back to the
			// caller
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, err
		}

		if _, err := creds.HandleFetchNodeCredentialsResponse(ctx, storage, fetchResp, opt...); err != nil {
			err := fmt.Errorf("error handling fetch creds response from server: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}

		// At this point if there is no error we have found and saved our
		// creds, and can proceed connecting
	}

	tlsConfigs, err := nodetls.ClientConfigs(ctx, creds, opt...)
	if err != nil {
		err := fmt.Errorf("error getting tls configs from node creds: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}
	if len(tlsConfigs) == 0 {
		err := errors.New("no valid tls client configs were returned")
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	// We have two configs: one will ask for a chain with the current CA cert,
	// and one with the next one (at least from the perspective of this client).
	// We could return one along with the IDs to use and have this code embed
	// one or the other but that seems more of a hassle than just ranging
	// through this and trying to connect.
	var tlsErrors error
	for _, tlsConfig := range tlsConfigs {
		nonTlsConn, err := nonTlsConnFn()
		if err != nil {
			err := fmt.Errorf("unable to dial to server: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}
		tlsConn := tls.Client(nonTlsConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tlsErrors = errors.Join(tlsErrors, fmt.Errorf("error handshaking tls connection: %w", err))
			continue
		}
		return tlsConn, nil
	}

	err = fmt.Errorf("errors encountered attempting to create client tls connection: %w", tlsErrors)
	opts.WithLogger.Error(err.Error(), "op", op)
	return nil, fmt.Errorf("(%s) %s", op, err.Error())
}

// attemptFetch creates a signed fetch request and tries to perform a TLS
// handshake, reading the resulting response
//
// If not authorized, returns nodeenrollment.ErrNotAuthorized
func attemptFetch(ctx context.Context, nonTlsConn net.Conn, creds *types.NodeCredentials, opt ...nodeenrollment.Option) (*types.FetchNodeCredentialsResponse, error) {
	const op = "nodeenrollment.protocol.attemptFetch"

	switch {
	case creds == nil:
		return nil, fmt.Errorf("(%s) nil creds", op)
	case creds.CertificatePrivateKeyPkcs8 == nil:
		return nil, fmt.Errorf("(%s) nil certificate private key", op)
	case creds.CertificatePublicKeyPkix == nil:
		return nil, fmt.Errorf("(%s) nil certificate public key", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	req, err := creds.CreateFetchNodeCredentialsRequest(ctx, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error creating fetch request: %w", op, err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(creds.CertificatePrivateKeyPkcs8)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing private key: %w", op, err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(creds.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing public key: %w", op, err)
	}

	reqMsg, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling request message: %w", op, err)
	}
	reqMsgString := base64.RawStdEncoding.EncodeToString(reqMsg)

	splitNextProtos, err := nodetls.BreakIntoNextProtos(nodeenrollment.FetchNodeCredsNextProtoV1Prefix, reqMsgString)
	if err != nil {
		return nil, fmt.Errorf("(%s) error splitting request into next protos: %w", op, err)
	}

	// We need to use TLS for the connection but we aren't relying on its
	// security. Create a self-signed cert and embed our info into it.
	template := &x509.Certificate{
		AuthorityKeyId: creds.CertificatePublicKeyPkix,
		SubjectKeyId:   creds.CertificatePublicKeyPkix,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{nodeenrollment.CommonDnsName},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(opts.WithNotBeforeClockSkew),
		NotAfter:              time.Now().Add(opts.WithNotAfterClockSkew),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(opts.WithRandomReader, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("(%s) error creating certificate: %w", op, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{
			certBytes,
		},
		PrivateKey: privKey,
	}

	tlsConf := &tls.Config{
		Rand: opts.WithRandomReader,
		GetClientCertificate: func(
			_ *tls.CertificateRequestInfo,
		) (*tls.Certificate, error) {
			return tlsCert, nil
		},
		MinVersion: tls.VersionTLS13,
		// We are using TLS as transport for signed, public information or
		// encrypted information only; we do not rely on it for security
		InsecureSkipVerify: true,
		NextProtos:         splitNextProtos,
		ServerName:         opts.WithServerName,
	}

	tlsConn := tls.Client(nonTlsConn, tlsConf)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		err := fmt.Errorf("error tls handshaking connection on client: %w", err)
		opts.WithLogger.Error(err.Error(), "op", op)
		return nil, fmt.Errorf("(%s) %s", op, err.Error())
	}

	commonName := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
	switch commonName {
	case nodeenrollment.CommonDnsName:
		// We're unauthorized
		return nil, nodeenrollment.ErrNotAuthorized

	default:
		// log.Println("common name was", commonName)
		respBytes, err := base64.RawStdEncoding.DecodeString(tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName)
		if err != nil {
			err := fmt.Errorf("error base-64 decoding fetch response: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}
		fetchResp := new(types.FetchNodeCredentialsResponse)
		if err := proto.Unmarshal(respBytes, fetchResp); err != nil {
			err := fmt.Errorf("error decoding response from server: %w", err)
			opts.WithLogger.Error(err.Error(), "op", op)
			return nil, fmt.Errorf("(%s) %s", op, err.Error())
		}

		return fetchResp, nil
	}
}
