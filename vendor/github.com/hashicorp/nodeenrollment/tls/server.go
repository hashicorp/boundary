// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"strings"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GenerateServerCertificates issues contemporaneous certificates for TLS
// connections from one or more root certificates.
//
// Valid options: WithRandomReader, WithStorageWrapper (passed through to
// LoadNodeInformation and LoadRootCertificates)
func GenerateServerCertificates(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.GenerateServerCertificatesRequest,
	opt ...nodeenrollment.Option,
) (*types.GenerateServerCertificatesResponse, error) {
	const op = "nodeenrollment.tls.GenerateServerCertificates"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	// We don't have a stored key to use for validation if we haven't authorized
	// the node yet, so in the fetch case we skip this step (we've still
	// validated, earlier, that the bundle is internally consistent; that the
	// signature matches the public key _on the request_ itself).
	if !req.SkipVerification {
		switch {
		case len(req.Nonce) == 0:
			return nil, fmt.Errorf("(%s) empty nonce", op)
		case len(req.NonceSignature) == 0:
			return nil, fmt.Errorf("(%s) empty nonce signature", op)
		}
		// Ensure node is authorized
		nodeIdStorage, ok := storage.(nodeenrollment.NodeIdLoader)
		switch {
		// If we have a NodeId & storage supports NodeIdLoader, use it
		case req.NodeId != "" && ok:
			nodeInfos, err := types.LoadNodeInformationSetByNodeId(ctx, nodeIdStorage, req.NodeId, opt...)
			if err != nil {
				return nil, err
			}
			authorized := false
			var errs error
			// We only need to find one valid NodeInfo for this nodeId to authorize the request
			for _, n := range nodeInfos.Nodes {
				err = verifyGenerateCertificatesRequest(n, req)
				if err != nil {
					errs = errors.Join(errs, err)
				}
				authorized = true
				break
			}
			if !authorized {
				return nil, fmt.Errorf("(%s) unable to authorize node information: %w", op, errs)
			}
		// Otherwise use the key id passed in
		default:
			keyId, err := nodeenrollment.KeyIdFromPkix(req.CertificatePublicKeyPkix)
			if err != nil {
				return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
			}
			nodeInfo, err := types.LoadNodeInformation(ctx, storage, keyId, opt...)
			if err != nil {
				return nil, fmt.Errorf("(%s) error loading node information: %w", op, err)
			}
			err = verifyGenerateCertificatesRequest(nodeInfo, req)
			if err != nil {
				return nil, err
			}
		}
	}

	resp := &types.GenerateServerCertificatesResponse{
		CertificatePrivateKeyType: types.KEYTYPE_ED25519,
		CertificateBundles:        make([]*types.CertificateBundle, 0, 2),
	}

	if len(req.ClientState) != 0 {
		clientState := new(structpb.Struct)
		if err := proto.Unmarshal(req.ClientState, clientState); err != nil {
			return nil, fmt.Errorf("(%s) error unmarshaling client state: %w", op, err)
		}
		resp.ClientState = clientState
	}

	// Now we're going to load the roots, generate a new key, and create a set
	// of certificates to use for whatever is acting as the server side to
	// present to the node (client) side
	roots, err := types.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error loading root certificates: %w", op, err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(opts.WithRandomReader)
	if err != nil {
		return nil, fmt.Errorf("(%s) error generating just-in-time cert key: %w", op, err)
	}

	resp.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling just-in-time cert key: %w", op, err)
	}
	resp.CertificatePrivateKeyType = types.KEYTYPE_ED25519

	for _, rootCert := range []*types.RootCertificate{roots.Current, roots.Next} {
		serverCert, signer, err := rootCert.SigningParams(ctx)
		if err != nil {
			return nil, fmt.Errorf("(%s) error getting signing params: %w", op, err)
		}

		keyId, err := nodeenrollment.KeyIdFromPkix(rootCert.PublicKeyPkix)
		if err != nil {
			return nil, fmt.Errorf("(%s) error deriving key id for root cert: %w", op, err)
		}

		template := &x509.Certificate{
			AuthorityKeyId: serverCert.SubjectKeyId,
			SubjectKeyId:   req.CertificatePublicKeyPkix,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			Subject: pkix.Name{
				CommonName: keyId,
			},
			DNSNames:     []string{keyId},
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
			SerialNumber: big.NewInt(mathrand.Int63()),
			NotBefore:    serverCert.NotBefore,
			NotAfter:     serverCert.NotAfter,
		}
		if len(req.Nonce) > 0 {
			template.DNSNames = append(template.DNSNames, base64.RawStdEncoding.EncodeToString(req.Nonce))
		}
		// log.Println("req common name", req.CommonName)
		if req.CommonName != "" {
			template.Subject.CommonName = req.CommonName
			template.DNSNames = append(template.DNSNames, req.CommonName)
		}

		leafCert, err := x509.CreateCertificate(opts.WithRandomReader, template, serverCert, pubKey, signer)
		if err != nil {
			return nil, fmt.Errorf("(%s) error creating certificate: %w", op, err)
		}

		resp.CertificateBundles = append(resp.CertificateBundles, &types.CertificateBundle{
			CertificateDer:       leafCert,
			CaCertificateDer:     serverCert.Raw,
			CertificateNotBefore: timestamppb.New(serverCert.NotBefore),
			CertificateNotAfter:  timestamppb.New(serverCert.NotAfter),
		})
	}

	return resp, nil
}

func verifyGenerateCertificatesRequest(nodeInfo *types.NodeInformation, req *types.GenerateServerCertificatesRequest) error {
	const op = "nodeenrollment.tls.verifyGenerateCertificatesRequest"

	// Validate the nonce
	nodePubKeyRaw, err := x509.ParsePKIXPublicKey(nodeInfo.CertificatePublicKeyPkix)
	if err != nil {
		return fmt.Errorf("(%s) node public key cannot be parsed: %w", op, err)
	}
	nodePubKey, ok := nodePubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("(%s) node public key cannot be interpreted as ed25519 public key: %w", op, err)
	}
	if !ed25519.Verify(nodePubKey, req.Nonce, req.NonceSignature) {
		return fmt.Errorf("(%s) nonce signature verification failed", op)
	}
	if len(req.ClientState) != 0 {
		if len(req.ClientStateSignature) == 0 {
			return fmt.Errorf("(%s) client state is not empty but state signature is", op)
		}
		if !ed25519.Verify(nodePubKey, req.ClientState, req.ClientStateSignature) {
			return fmt.Errorf("(%s) client state signature verification failed", op)
		}
	}
	return nil
}

// ServerConfig takes in a generate response and turns it into a server-side TLS
// configuration
//
// Supported options: WithServerName, which will be the value used in the
// cert map for lookup; also, options passed in here will be passed through to
// the standard TLS configuration function (useful for tests, mainly)
func ServerConfig(
	ctx context.Context,
	in *types.GenerateServerCertificatesResponse,
	opt ...nodeenrollment.Option,
) (*tls.Config, error) {
	const op = "nodeenrollment.tls.ServerConfig"

	switch {
	case in == nil:
		return nil, fmt.Errorf("(%s) nil input", op)
	case len(in.CertificatePrivateKeyPkcs8) == 0:
		return nil, fmt.Errorf("(%s) nil private key in input", op)
	case in.CertificatePrivateKeyType != types.KEYTYPE_ED25519:
		return nil, fmt.Errorf("(%s) unsupported private key type in input", op)
	case len(in.CertificateBundles) != 2:
		return nil, fmt.Errorf("(%s) invalid input certificate bundles, wanted 2 bundles, got %d", op, len(in.CertificateBundles))
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(in.CertificatePrivateKeyPkcs8)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing private key: %w", op, err)
	}

	rootPool := x509.NewCertPool()

	type certBundle struct {
		leaf *x509.Certificate
		ca   *x509.Certificate
	}
	certMap := map[string]*certBundle{}

	now := time.Now()

	for _, bundle := range in.CertificateBundles {
		//
		// Parse server certificate
		//
		leafCert, err := x509.ParseCertificate(bundle.CertificateDer)
		if err != nil {
			return nil, fmt.Errorf("(%s) error parsing leaf certificate: %w", op, err)
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
			return nil, fmt.Errorf("(%s) error parsing ca certificate: %w", op, err)
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

		caCertPkixPubKey, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling ca cert pub key: %w", op, err)
		}
		caCertKeyId, err := nodeenrollment.KeyIdFromPkix(caCertPkixPubKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error deriving key id from ca cert pub key: %w", op, err)
		}

		certMap[caCertKeyId] = &certBundle{
			leaf: leafCert,
			ca:   caCert,
		}

		// log.Println("server side adding", caCertKeyId, "to certMap")

		// If a server name is given, add it to the map. One of the ways this is
		// used is during fetching, where we don't have a key ID; we pass in the
		// standard name here, and the fetch attempt on the other side will use
		// it during the handshake.
		if opts.WithServerName != "" && certMap[opts.WithServerName] == nil {
			// log.Println("server side adding", opts.WithServerName, "to certMap via opts.WithServerName")
			certMap[opts.WithServerName] = &certBundle{
				leaf: leafCert,
				ca:   caCert,
			}
		}
	}

	tlsConf, err := standardTlsConfig(ctx, rootPool, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error generating standard tls config: %w", op, err)
	}

	tlsConf.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		var certificateSelector string
		for _, proto := range hello.SupportedProtos {
			if strings.HasPrefix(proto, nodeenrollment.CertificatePreferenceV1Prefix) {
				certificateSelector = strings.TrimPrefix(proto, nodeenrollment.CertificatePreferenceV1Prefix)
				break
			}
		}
		// If we don't find a certificate selector it's an older client. If a
		// server name was provided, use that; if not just pick something and
		// hope for the best, which is basically the old logic anyways...
		// log.Println("GetCertificate", certificateSelector)
		if certificateSelector == "" {
			certificateSelector = opts.WithServerName
		}
		if certificateSelector == "" {
			for k := range certMap {
				certificateSelector = k
				break
			}
		}
		bundle := certMap[certificateSelector]
		if bundle == nil {
			// log.Println("GetCertificate, selector not found", certificateSelector)
			return nil, nil
		}
		return &tls.Certificate{
			Certificate: [][]byte{
				bundle.leaf.Raw,
				bundle.ca.Raw,
			},
			PrivateKey: privKey,
			Leaf:       bundle.leaf,
		}, nil
	}

	return tlsConf, nil
}
