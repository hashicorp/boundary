// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package registration

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"golang.org/x/crypto/curve25519"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// AuthorizeNode authorizes a node via a registration request.
//
// Note: THIS IS NOT A CONCURRENCY SAFE FUNCTION. In most cases, the given
// storage should ensure concurrency safety; as examples, version numbers could
// be used within NodeInformation's "state" parameter, or the application using
// this library could implement a higher-level lock on the API that leads to
// calling this function. Failing to account for concurrency could mean that two
// calls to AuthorizeNode running concurrently result in different
// certificate/encryption parameters being saved on the server vs. sent to the
// node.
//
// Supported options: WithStorageWrapper (passed through to LoadNodeInformation,
// LoadRootCertificates, and NodeInformation.Store), WithState (set into the
// stored NodeInformation), WithNotBeforeClockSkew/WithNotAfterClockSkew (passed
// through to validateFetchRequest), WithSkipStorage, WithRandomReader
func AuthorizeNode(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.FetchNodeCredentialsRequest,
	opt ...nodeenrollment.Option,
) (*types.NodeInformation, error) {
	const op = "nodeenrollment.registration.AuthorizeNode"

	// We expect to see the final call in validateFetchRequestCommon to
	// LoadNodeInformation to return here with nil nodeInfo and ErrNotFound
	reqInfo, err := validateFetchRequestCommon(ctx, storage, req, opt...)
	switch {
	case err != nil:
		return nil, fmt.Errorf("(%s) error during fetch request validation: %w", op, err)

	case len(reqInfo.Nonce) != nodeenrollment.NonceSize:
		// Not a normal request, possibly one containing server-led activation
		// token, which should not use this path
		return nil, fmt.Errorf("(%s) server-led activation tokens cannot be used with node-led authorize call", op)

	default:
		// Check for existing node information for this keyId
		keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
		if err != nil {
			return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
		}
		nodeInfo, err := types.LoadNodeInformation(ctx, storage, keyId, opt...)
		switch {
		case err == nil || nodeInfo != nil:
			return nil, fmt.Errorf("(%s) authorize node cannot be called on an existing node", op)
		case !errors.Is(err, nodeenrollment.ErrNotFound):
			return nil, fmt.Errorf("(%s) error checking for node information from storage: %w", op, err)
		default:
			// We got not found, which is what we want
		}
	}

	return authorizeNodeCommon(ctx, storage, reqInfo, opt...)
}

// Note: unlike AuthorizeNode, which can be called directly, this internal
// function can be called from various paths and does not ensure that a node
// does not already exist; in some registration flows that's actually completely
// fine (e.g. with wrapper)
func authorizeNodeCommon(
	ctx context.Context,
	storage nodeenrollment.Storage,
	reqInfo *types.FetchNodeCredentialsInfo,
	opt ...nodeenrollment.Option,
) (*types.NodeInformation, error) {
	const op = "nodeenrollment.registration.authorizeNodeCommon"
	keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nodeInfo := &types.NodeInformation{
		Id:                               keyId,
		CertificatePublicKeyPkix:         reqInfo.CertificatePublicKeyPkix,
		CertificatePublicKeyType:         reqInfo.CertificatePublicKeyType,
		PreviousCertificatePublicKeyPkix: reqInfo.PreviousCertificatePublicKeyPkix,
		EncryptionPublicKeyBytes:         reqInfo.EncryptionPublicKeyBytes,
		EncryptionPublicKeyType:          reqInfo.EncryptionPublicKeyType,
		RegistrationNonce:                reqInfo.Nonce,
		State:                            opts.WithState,
		WrappingRegistrationFlowInfo:     reqInfo.WrappingRegistrationFlowInfo,
	}

	certPubKeyRaw, err := x509.ParsePKIXPublicKey(nodeInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing node certificate public key: %w", op, err)
	}
	certPubKey, ok := certPubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("(%s) unable to interpret node certificate public key as an ed25519 public key", op)
	}

	rootCerts, err := types.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error fetching current root certificates: %w", op, err)
	}

	// Create certificates
	{
		for _, rootCert := range []*types.RootCertificate{rootCerts.Current, rootCerts.Next} {
			caCert, caPrivKey, err := rootCert.SigningParams(ctx)
			if err != nil {
				return nil, fmt.Errorf("(%s) error parsing signing parameters from root: %w", op, err)
			}

			template := &x509.Certificate{
				AuthorityKeyId: caCert.SubjectKeyId,
				SubjectKeyId:   nodeInfo.CertificatePublicKeyPkix,
				ExtKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
				},
				Subject: pkix.Name{
					CommonName: nodeInfo.Id,
				},
				DNSNames:     []string{nodeInfo.Id},
				KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
				SerialNumber: big.NewInt(mathrand.Int63()),
				NotBefore:    caCert.NotBefore,
				NotAfter:     caCert.NotAfter,
			}

			// TODO: After enough time, remove this; it's here because
			// verification code used to expect it, but these days we want to
			// only use it in the context of fetching
			template.DNSNames = append(template.DNSNames, nodeenrollment.CommonDnsName)

			certificateDer, err := x509.CreateCertificate(opts.WithRandomReader, template, caCert, ed25519.PublicKey(certPubKey), caPrivKey)
			if err != nil {
				return nil, fmt.Errorf("(%s) error creating certificate: %w", op, err)
			}

			nodeInfo.CertificateBundles = append(nodeInfo.CertificateBundles, &types.CertificateBundle{
				CertificateDer:       certificateDer,
				CaCertificateDer:     rootCert.CertificateDer,
				CertificateNotBefore: timestamppb.New(template.NotBefore),
				CertificateNotAfter:  timestamppb.New(template.NotAfter),
			})
		}
	}

	// Create server encryption keys
	{
		nodeInfo.ServerEncryptionPrivateKeyBytes = make([]byte, curve25519.ScalarSize)
		n, err := opts.WithRandomReader.Read(nodeInfo.ServerEncryptionPrivateKeyBytes)
		switch {
		case err != nil:
			return nil, fmt.Errorf("(%s) error reading random bytes to generate server encryption key: %w", op, err)
		case n != curve25519.ScalarSize:
			return nil, fmt.Errorf("(%s) wrong number of random bytes read when generating server encryption key, expected %d but got %d", op, curve25519.ScalarSize, n)
		}
		nodeInfo.ServerEncryptionPrivateKeyType = types.KEYTYPE_X25519
	}

	// Save the node information into storage if not skipped
	if !opts.WithSkipStorage {
		if err := nodeInfo.Store(ctx, storage, opt...); err != nil {
			// If using a storage implementation where Store does not overwrite existing records, detect
			// and handle receiving duplicate reqInfo by returning the stored nodeInfo
			var dre *types.DuplicateRecordError
			if errors.As(err, &dre) || errors.As(err, &types.DuplicateRecordError{}) {
				loadNodeInfo, err := types.LoadNodeInformation(ctx, storage, nodeInfo.Id)
				if err == nil {
					return loadNodeInfo, nil
				}
				err = fmt.Errorf("(%s) error loading node information after duplicate record detected: %w", op, err)
			}
			return nil, fmt.Errorf("(%s) error updating registration information: %w", op, err)
		}
	}

	return nodeInfo, nil
}
