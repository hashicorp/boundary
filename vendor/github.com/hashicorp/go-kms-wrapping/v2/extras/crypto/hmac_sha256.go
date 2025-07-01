// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
)

// HmacSha256WithPrk will HmacSha256 using the provided prk.  See HmacSha256 for
// options supported.
func HmacSha256WithPrk(ctx context.Context, data, prk []byte, opt ...wrapping.Option) (string, error) {
	opt = append(opt, WithPrk(prk))
	return HmacSha256(ctx, data, nil, opt...)
}

// HmacSha256 the provided data. Supports WithSalt, WithInfo, WithPrefix,
// WithEd25519, WithPrk, WithMarshaledSigInfo, WithBase64Encoding,
// WithBase58Encoding options. WithEd25519 is a "legacy" way to complete this
// operation and should not be used in new operations unless backward
// compatibility is needed. The WithPrefix option will prepend the prefix to the
// hmac-sha256 value.
func HmacSha256(ctx context.Context, data []byte, cipher wrapping.Wrapper, opt ...wrapping.Option) (string, error) {
	const op = "crypto.HmacSha256"
	opts, err := getOpts(opt...)
	if err != nil {
		return "", fmt.Errorf("%s: unable to get options: %w", op, err)
	}
	if data == nil {
		return "", fmt.Errorf("%s: missing data: %w", op, wrapping.ErrInvalidParameter)
	}
	if cipher == nil && opts.withPrk == nil {
		return "", fmt.Errorf("%s: you must specify either a wrapper or prk: %w", op, wrapping.ErrInvalidParameter)
	}
	if cipher != nil && opts.withPrk != nil {
		return "", fmt.Errorf("%s: you cannot specify both a wrapper or prk: %w", op, wrapping.ErrInvalidParameter)
	}
	if opts.withEd25519 && opts.withPrk != nil {
		return "", fmt.Errorf("%s: you cannot specify both ed25519 and a prk: %w", op, wrapping.ErrInvalidParameter)
	}
	if opts.withBase58Encoding && opts.withBase64Encoding {
		return "", fmt.Errorf("%s: you cannot specify both WithBase58Encoding and WithBase64Encoding: %w", op, wrapping.ErrInvalidParameter)
	}
	var key [32]byte
	switch {
	case opts.withPrk != nil:
		key = blake2b.Sum256(opts.withPrk)

	case opts.withEd25519:
		reader, err := NewDerivedReader(ctx, cipher, 32, opt...)
		if err != nil {
			return "", fmt.Errorf("%s: %w", op, err)
		}
		edKey, _, err := ed25519.GenerateKey(reader)
		if err != nil {
			return "", fmt.Errorf("%s: unable to generate derived key: %w", op, wrapping.ErrInvalidParameter)
		}
		n := copy(key[:], edKey)
		if n != 32 {
			return "", fmt.Errorf("%s: expected to copy 32 bytes and got: %d", op, n)
		}

	default:
		reader, err := NewDerivedReader(ctx, cipher, 32, opt...)
		if err != nil {
			return "", fmt.Errorf("%s: %w", op, err)
		}
		readerKey := make([]byte, 32)
		n, err := io.ReadFull(reader, readerKey)
		if err != nil {
			return "", fmt.Errorf("%s: %w", op, err)
		}
		if n != 32 {
			return "", fmt.Errorf("%s: expected to read 32 bytes and got: %d", op, n)
		}
		key = blake2b.Sum256(readerKey)
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(data)
	hmac := mac.Sum(nil)

	if opts.withMarshaledSigInfo {
		keyId, err := cipher.KeyId(ctx)
		if err != nil {
			return "", fmt.Errorf("%s: error retrieving key id: %w", op, err)
		}
		si := &wrapping.SigInfo{
			Signature: hmac,
			KeyInfo: &wrapping.KeyInfo{
				KeyId:       keyId,
				KeyPurposes: []wrapping.KeyPurpose{wrapping.KeyPurpose_Sign},
			},
			HmacType: wrapping.HmacType_Sha256.Enum(),
		}
		enc, err := proto.Marshal(si)
		if err != nil {
			return "", fmt.Errorf("%s: error encoding as sig info: %w", op, err)
		}
		hmac = enc
	}

	var hmacString string
	switch {
	case opts.withBase64Encoding:
		hmacString = base64.RawURLEncoding.EncodeToString(hmac)
	case opts.withBase58Encoding:
		hmacString = base58.Encode(hmac)
	default:
		hmacString = string(hmac)
	}
	if opts.withPrefix != "" {
		return opts.withPrefix + hmacString, nil
	}
	return hmacString, nil
}
