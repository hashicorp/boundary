// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/hashicorp/nodeenrollment"
)

// standardTlsConfig returns a tls config suitable for either client or server
// use with our custom settings/verification logic
//
// Generally this will not be used on its own, but will be called by other parts
// of the library that will further customize the configuration and provide
// appropriate roots.
//
// Supported options: WithRandomReader, WithNonce, WithVerifyConnectionFunc,
// WithExpectedPublicKey, WithServerName
func standardTlsConfig(_ context.Context, pool *x509.CertPool, opt ...nodeenrollment.Option) (*tls.Config, error) {
	const op = "nodeenrollment.tls.standardTlsConfig"

	switch {
	case pool == nil:
		return nil, fmt.Errorf("(%s) nil ca pool provided", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	verifyOpts := x509.VerifyOptions{
		Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}
	if opts.WithNonce != "" {
		verifyOpts.DNSName = opts.WithNonce
	}
	if opts.WithTlsVerifyOptionsFunc != nil {
		verifyOpts = opts.WithTlsVerifyOptionsFunc(pool)
	}
	// log.Println("creating tls config with server name", opts.WithServerName)
	tlsConfig := &tls.Config{
		Rand:               opts.WithRandomReader,
		ClientAuth:         tls.RequireAnyClientCert,
		MinVersion:         tls.VersionTLS13,
		RootCAs:            pool,
		ClientCAs:          pool,
		InsecureSkipVerify: true,
		ServerName:         opts.WithServerName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("(%s) no peer certificates in VerifyConnection", op)
			}
			if opts.WithAlpnProtoPrefix == nodeenrollment.FetchNodeCredsNextProtoV1Prefix {
				// We are always skipping verification in this case as we either
				// are returning unauthorized or are returning an encrypted
				// value.
				return nil
			}
			leaf := cs.PeerCertificates[0]
			if _, err := leaf.Verify(verifyOpts); err != nil {
				return fmt.Errorf("(%s) error verifying peer certificate: %w", op, err)
			}
			if len(opts.WithExpectedPublicKey) != 0 && subtle.ConstantTimeCompare(opts.WithExpectedPublicKey, leaf.SubjectKeyId) != 1 {
				return fmt.Errorf("(%s) subject key ID does not match: %w", op, err)
			}
			return nil
		},
	}

	return tlsConfig, nil
}
