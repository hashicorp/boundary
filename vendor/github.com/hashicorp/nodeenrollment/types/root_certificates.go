// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/proto"
)

// Store stores the certificates to the given storage, possibly encrypting
// secret values along the way if a wrapper is passed
//
// Supported options: WithStorageWrapper
func (r *RootCertificates) Store(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) error {
	const op = "nodeenrollment.types.(RootCertificates).Store"

	switch {
	case nodeenrollment.IsNil(storage):
		return fmt.Errorf("(%s) storage is nil", op)

	case nodeenrollment.IsNil(r):
		return fmt.Errorf("(%s) root certificates is nil", op)

	case r.Id != nodeenrollment.RootsMessageId:
		return fmt.Errorf("(%s) expected id of %q for roots but got %q", op, nodeenrollment.RootsMessageId, r.Id)

	case r.Current == nil:
		return fmt.Errorf("(%s) curent root certificate is nil", op)

	case r.Next == nil:
		return fmt.Errorf("(%s) curent root certificate is nil", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	// First perform basic validation on both roots before modifying either
	for _, root := range []*RootCertificate{r.Current, r.Next} {
		if len(root.PrivateKeyPkcs8) == 0 {
			// This isn't really a validation function, but we want to avoid
			// wrapping a nil key so we do a check here
			return fmt.Errorf("(%s) refusing to store root %s with no private key", op, root)
		}

		switch nodeenrollment.KnownId(root.Id) {
		case nodeenrollment.MissingId:
			return fmt.Errorf("(%s) %s root is missing id", op, root)
		case nodeenrollment.CurrentId, nodeenrollment.NextId:
		default:
			return fmt.Errorf("(%s) invalid root certificate id", op)
		}
	}

	// Now do the actual saving
	rootsToStore := r
	if opts.WithStorageWrapper != nil {
		rootsToStore = proto.Clone(r).(*RootCertificates)

		keyId, err := opts.WithStorageWrapper.KeyId(ctx)
		if err != nil {
			return fmt.Errorf("(%s) error reading wrapper key id: %w", op, err)
		}
		rootsToStore.WrappingKeyId = keyId

		for _, root := range []*RootCertificate{rootsToStore.Current, rootsToStore.Next} {
			blobInfo, err := opts.WithStorageWrapper.Encrypt(
				ctx,
				root.PrivateKeyPkcs8,
				wrapping.WithAad(root.PublicKeyPkix),
			)
			if err != nil {
				return fmt.Errorf("(%s) error wrapping private key for root %s: %w", op, root, err)
			}
			root.PrivateKeyPkcs8, err = proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling wrapped private key for root %s: %w", op, root, err)
			}
		}
	}

	if opts.WithState != nil {
		rootsToStore.State = opts.WithState
	}

	if err := storage.Store(ctx, rootsToStore); err != nil {
		return fmt.Errorf("(%s) error storing root certificates: %w", op, err)
	}

	return nil
}

// LoadRootCertificates loads the RootCertificates from storage, unwrapping
// encrypted values if needed
//
// Supported options: WithStorageWrapper
func LoadRootCertificates(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) (*RootCertificates, error) {
	const op = "nodeenrollment.types.LoadRootCertificates"

	if nodeenrollment.IsNil(storage) {
		return nil, fmt.Errorf("(%s) storage is nil", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	roots := &RootCertificates{
		Id: string(nodeenrollment.RootsMessageId),
	}
	if err := storage.Load(ctx, roots); err != nil {
		return nil, fmt.Errorf("(%s) error loading certificates from storage: %w", op, err)
	}

	switch {
	case roots.Current == nil:
		return nil, fmt.Errorf("(%s) current root is nil", op)

	case roots.Next == nil:
		return nil, fmt.Errorf("(%s) next root is nil", op)

	case opts.WithStorageWrapper == nil && roots.WrappingKeyId != "":
		return nil, fmt.Errorf("(%s) roots has encrypted parts with wrapper key id %q but wrapper not provided", op, roots.WrappingKeyId)

	case roots.WrappingKeyId != "":
		// Note: not checking the key IDs against each other because if using
		// something like a PooledWrapper then the current encrypting ID may not
		// match, or if the wrapper performs its own internal key selection.
		for _, root := range []*RootCertificate{roots.Current, roots.Next} {
			blobInfo := new(wrapping.BlobInfo)
			if err := proto.Unmarshal(root.PrivateKeyPkcs8, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling private key blob info for %s root: %w", op, root, err)
			}
			pt, err := opts.WithStorageWrapper.Decrypt(
				ctx,
				blobInfo,
				wrapping.WithAad(root.PublicKeyPkix),
			)
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting private key for %s root: %w", op, root, err)
			}
			root.PrivateKeyPkcs8 = pt
		}

		roots.WrappingKeyId = ""
	}

	return roots, nil
}

// SigningParams is a helper to extract the necessary information from the
// RootCertificate to use as a CA certificate
func (r *RootCertificate) SigningParams(ctx context.Context) (*x509.Certificate, crypto.Signer, error) {
	const op = "nodeenrollment.types.(RootCertificate).SigningParams"
	switch {
	case nodeenrollment.IsNil(r):
		return nil, nil, fmt.Errorf("(%s) root certificate is nil", op)
	case len(r.PrivateKeyPkcs8) == 0:
		return nil, nil, fmt.Errorf("(%s) no private key found in root", op)
	case r.PrivateKeyType == KEYTYPE_UNSPECIFIED:
		return nil, nil, fmt.Errorf("(%s) private key type information not found in root", op)
	case len(r.CertificateDer) == 0:
		return nil, nil, fmt.Errorf("(%s) no certificate found in root", op)
	}

	var (
		signer crypto.Signer
		cert   *x509.Certificate
	)

	// Parse private key
	{
		switch r.PrivateKeyType {
		case KEYTYPE_ED25519:
			raw, err := x509.ParsePKCS8PrivateKey(r.PrivateKeyPkcs8)
			if err != nil {
				return nil, nil, fmt.Errorf("(%s) error unmarshaling private key: %w", op, err)
			}
			var ok bool
			signer, ok = raw.(ed25519.PrivateKey)
			if !ok {
				return nil, nil, fmt.Errorf("(%s) unmarshalled private key is not expected type, has type %T", op, raw)
			}

		default:
			return nil, nil, fmt.Errorf("(%s) unsupported private key type %v", op, r.PrivateKeyType.String())
		}
	}

	// Parse certificate
	{
		var err error
		cert, err = x509.ParseCertificate(r.CertificateDer)
		switch {
		case err != nil:
			return nil, nil, fmt.Errorf("(%s) error parsing certificate bytes: %w", op, err)
		case cert == nil:
			return nil, nil, fmt.Errorf("(%s) nil key after parsing certificate bytes", op)
		}
	}

	return cert, signer, nil
}
