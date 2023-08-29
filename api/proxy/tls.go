package proxy

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	targetspb "github.com/hashicorp/boundary/api/internal/pbs/controller/api/resources/targets"
)

// ClientTlsConfig creates a TLS configuration from the session authorization
// data and host
func ClientTlsConfig(sessionAuthzData *targetspb.SessionAuthorizationData, host string) (*tls.Config, error) {
	const op = "proxy.ClientTlsConfig"
	if sessionAuthzData == nil {
		return nil, fmt.Errorf("%s: nil session authorization data", op)
	}
	parsedCert, err := x509.ParseCertificate(sessionAuthzData.Certificate)
	if err != nil {
		return nil, fmt.Errorf("unable to decode mTLS certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{sessionAuthzData.Certificate},
				PrivateKey:  ed25519.PrivateKey(sessionAuthzData.PrivateKey),
				Leaf:        parsedCert,
			},
		},
		ServerName: host,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1", sessionAuthzData.SessionId},

		// This is set this way so we can make use of VerifyConnection, which we
		// set on this TLS config below. We are not skipping verification!
		InsecureSkipVerify: true,
	}
	if host == "" {
		tlsConf.ServerName = parsedCert.DNSNames[0]
	}

	// We disable normal DNS SAN behavior as we don't rely on DNS or IP
	// addresses for security and want to avoid issues with including localhost
	// etc.
	verifyOpts := x509.VerifyOptions{
		DNSName: sessionAuthzData.SessionId,
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

	return tlsConf, nil
}
