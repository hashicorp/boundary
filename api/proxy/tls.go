// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
)

// clientTlsConfig creates a TLS configuration to connect to a worker proxy, or
// returns a cached config
//
// Supported options: WithWorkerHost
func (p *ClientProxy) clientTlsConfig(opt ...Option) (*tls.Config, error) {
	if p.clientTlsConf != nil {
		return p.clientTlsConf, nil
	}

	const op = "proxy.clientTlsConfig"
	if p.sessionAuthzData == nil {
		return nil, fmt.Errorf("%s: nil session authorization data", op)
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: error getting options: %w", op, err)
	}

	var workerHost string
	if opts.WithWorkerHost == nil {
		workerHost, _, err = net.SplitHostPort(p.workerAddr)
		if err != nil {
			if strings.Contains(err.Error(), "missing port") {
				workerHost = p.workerAddr
			} else {
				return nil, fmt.Errorf("%s: error splitting worker adddress host/port: %w", op, err)
			}
		}
	}

	parsedCert, err := x509.ParseCertificate(p.sessionAuthzData.Certificate)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to decode mTLS certificate: %w", op, err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{p.sessionAuthzData.Certificate},
				PrivateKey:  ed25519.PrivateKey(p.sessionAuthzData.PrivateKey),
				Leaf:        parsedCert,
			},
		},
		ServerName: workerHost,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1", p.sessionAuthzData.SessionId},

		// This is set this way so we can make use of VerifyConnection, which we
		// set on this TLS config below. We are not skipping verification!
		InsecureSkipVerify: true,
	}

	if workerHost == "" {
		tlsConf.ServerName = parsedCert.DNSNames[0]
	}

	// We disable normal DNS SAN behavior as we don't rely on DNS or IP
	// addresses for security and want to avoid issues with including localhost
	// etc.
	verifyOpts := x509.VerifyOptions{
		DNSName: p.sessionAuthzData.SessionId,
		Roots:   certPool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}
	tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
		// Go will not run this without at least one peer certificate, but
		// doesn't hurt to check
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("%s: no peer certificates provided", op)
		}
		_, err := cs.PeerCertificates[0].Verify(verifyOpts)
		return err
	}

	p.clientTlsConf = tlsConf
	return tlsConf, nil
}
