// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// ClientConfigs creates client-side tls.Config by from the given
// NodeCredentials. The values populated here can be used or modified as needed.
// There are two to represent using current and next as the certificate selector
// passed via ALPN, so dials can be attempted with either.
//
// Supported options: WithRandomReader, WithServerName (passed through to
// standardTlsConfig), WithExtraAlpnProtos, WithState
func ClientConfigs(ctx context.Context, n *types.NodeCredentials, opt ...nodeenrollment.Option) ([]*tls.Config, error) {
	const op = "nodeenrollment.tls.ClientConfigs"

	switch {
	case n == nil:
		return nil, fmt.Errorf("(%s) nil input", op)
	case len(n.CertificatePrivateKeyPkcs8) == 0:
		return nil, fmt.Errorf("(%s) no certificate private key", op)
	case n.CertificatePrivateKeyType != types.KEYTYPE_ED25519:
		return nil, fmt.Errorf("(%s) unsupported certificate private key type %s", op, n.CertificatePrivateKeyType.String())
	case len(n.CertificateBundles) != 2:
		return nil, fmt.Errorf("(%s) invalid certificate bundles found in credentials, wanted 2, got %d", op, len(n.CertificateBundles))
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	var signer crypto.Signer
	// Parse certificate private key
	{
		key, err := x509.ParsePKCS8PrivateKey(n.CertificatePrivateKeyPkcs8)
		switch {
		case err != nil:
			return nil, fmt.Errorf("(%s) error parsing certificate private key bytes: %w", op, err)
		case key == nil:
			return nil, fmt.Errorf("(%s) nil key after parsing certificate private key bytes", op)
		case n.CertificatePrivateKeyType == types.KEYTYPE_ED25519:
			var ok bool
			if signer, ok = key.(ed25519.PrivateKey); !ok {
				return nil, fmt.Errorf("(%s) certificate key cannot be understood as ed25519 private key", op)
			}
		default:
			return nil, fmt.Errorf("(%s) after parsing certificate private key information no signer found", op)
		}
	}

	nonceBytes := make([]byte, nodeenrollment.NonceSize)
	w, err := opts.WithRandomReader.Read(nonceBytes)
	if err != nil {
		return nil, fmt.Errorf("(%s) error generating nonce: %w", op, err)
	}
	if w != nodeenrollment.NonceSize {
		return nil, fmt.Errorf("(%s) invalid number of nonce bytes read, expected %d, got %d", op, nodeenrollment.NonceSize, w)
	}
	sigNonceBytes, err := signer.Sign(opts.WithRandomReader, nonceBytes, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("(%s) error signing certs request nonce: %w", op, err)
	}

	var clientStateBytes []byte
	var sigClientStateBytes []byte
	if opts.WithState != nil {
		clientStateBytes, err = proto.Marshal(opts.WithState)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling client state: %w", op, err)
		}
		sigClientStateBytes, err = signer.Sign(opts.WithRandomReader, clientStateBytes, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("(%s) error signing certs request client state: %w", op, err)
		}
	}

	// This may seem like an unintuitive name given this is a client, but it's
	// really a request for the other side to present a server cert that is
	// valid and with the embedded nonce.
	req := &types.GenerateServerCertificatesRequest{
		CertificatePublicKeyPkix: n.CertificatePublicKeyPkix,
		Nonce:                    nonceBytes,
		NonceSignature:           sigNonceBytes,
		ClientState:              clientStateBytes,
		ClientStateSignature:     sigClientStateBytes,
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling certs request: %w", op, err)
	}
	reqStr := base64.RawStdEncoding.EncodeToString(reqBytes)

	rootPool := x509.NewCertPool()

	type certBundle struct {
		leaf *x509.Certificate
		ca   *x509.Certificate
	}
	certMap := map[string]*certBundle{}

	now := time.Now()
	for _, bundle := range n.CertificateBundles {
		//
		// Parse node certificate
		//
		var err error
		leafCert, err := x509.ParseCertificate(bundle.CertificateDer)
		if err != nil {
			return nil, fmt.Errorf("(%s) error parsing node certificate bytes: %w", op, err)
		}
		if leafCert == nil {
			return nil, fmt.Errorf("(%s) after parsing node cert found empty value", op)
		}
		// It's expired
		if leafCert.NotAfter.Before(now) {
			continue
		}
		// It's not yet valid
		if leafCert.NotBefore.After(now) {
			continue
		}

		//
		// Parse CA certificate
		//
		caCert, err := x509.ParseCertificate(bundle.CaCertificateDer)
		if err != nil {
			return nil, fmt.Errorf("(%s) error parsing ca certificate bytes: %w", op, err)
		}
		if caCert == nil {
			return nil, fmt.Errorf("(%s) after parsing ca cert found empty value", op)
		}
		// It's expired
		if caCert.NotAfter.Before(now) {
			continue
		}
		// It's not yet valid
		if caCert.NotBefore.After(now) {
			continue
		}
		rootPool.AddCert(caCert)

		caCertKkixPubKey, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling ca cert pub key: %w", op, err)
		}
		caCertKeyId, err := nodeenrollment.KeyIdFromPkix(caCertKkixPubKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error deriving key id from ca cert pub key: %w", op, err)
		}

		certMap[caCertKeyId] = &certBundle{
			leaf: leafCert,
			ca:   caCert,
		}
		// log.Println("client side adding", keyId, "to certMap")
	}

	// Require nonce in DNS names in verification function
	opt = append(opt, nodeenrollment.WithNonce(base64.RawStdEncoding.EncodeToString(nonceBytes)))

	// Get a config for each valid client cert, identified using SNI to pick the
	// chain on the other end
	var tlsConfigs []*tls.Config
	for caCertKeyId := range certMap {
		tlsConfig, err := standardTlsConfig(ctx, rootPool, opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) error fetching standard tls config: %w", op, err)
		}

		tlsConfig.NextProtos, err = BreakIntoNextProtos(nodeenrollment.AuthenticateNodeNextProtoV1Prefix, reqStr)
		if err != nil {
			return nil, fmt.Errorf("(%s) error breaking request into next protos: %w", op, err)
		}
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, opts.WithExtraAlpnProtos...)
		// Add the certificate selector
		tlsConfig.NextProtos = append(tlsConfig.NextProtos,
			fmt.Sprintf("%s%s", nodeenrollment.CertificatePreferenceV1Prefix, caCertKeyId))

		// This function will look at the incoming CAs, identified by their
		// subject key, and look for a known cert chain we have that is from
		// that key
		tlsConfig.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			for _, acceptableCa := range cri.AcceptableCAs {
				// log.Println("GetClientCertificate", base64.RawStdEncoding.EncodeToString(acceptableCa))
				for _, bundle := range certMap {
					if subtle.ConstantTimeCompare(bundle.ca.RawSubject, acceptableCa) == 1 {
						return &tls.Certificate{
							Certificate: [][]byte{
								bundle.leaf.Raw,
								bundle.ca.Raw,
							},
							PrivateKey: signer,
							Leaf:       bundle.leaf,
						}, nil
					}
				}
			}
			return nil, fmt.Errorf("(%s) did not find a certificate acceptable to server roots", op)
		}

		tlsConfigs = append(tlsConfigs, tlsConfig)
	}

	return tlsConfigs, nil
}
