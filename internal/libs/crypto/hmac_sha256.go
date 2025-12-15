// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
)

// HmacSha256WithPrk will HmacSha256 using the provided prk.  See HmacSha256 for
// options supported.
func HmacSha256WithPrk(ctx context.Context, data, prk []byte, opt ...Option) (string, error) {
	opt = append(opt, WithPrk(prk))
	return HmacSha256(ctx, data, nil, nil, nil, opt...)
}

// HmacSha256 the provided data. Supports WithPrefix, WithEd25519 and WithPrk
// options. WithEd25519 is a "legacy" way to complete this operation and should
// not be used in new operations unless backward compatibility is needed. The
// WithPrefix option will prepend the prefix to the hmac-sha256 value.
func HmacSha256(ctx context.Context, data []byte, cipher wrapping.Wrapper, salt, info []byte, opt ...Option) (string, error) {
	const op = "crypto.HmacSha256"
	opts, err := getOpts(opt...)
	if err != nil {
		return "", fmt.Errorf("%s: unable to get options: %w", op, err)
	}
	if data == nil {
		return "", fmt.Errorf("%s: missing data: %w", op, ErrInvalidParameter)
	}
	if cipher == nil && opts.withPrk == nil {
		return "", fmt.Errorf("%s: you must specify either a wrapper or prk: %w", op, ErrInvalidParameter)
	}
	if cipher != nil && opts.withPrk != nil {
		return "", fmt.Errorf("%s: you cannot specify both a wrapper or prk: %w", op, ErrInvalidParameter)
	}
	if opts.withEd25519 && opts.withPrk != nil {
		return "", fmt.Errorf("%s: you cannot specify both ed25519 and a prk: %w", op, ErrInvalidParameter)
	}
	var key [32]byte
	switch {
	case opts.withPrk != nil:
		key = blake2b.Sum256(opts.withPrk)

	case opts.withEd25519:
		reader, err := NewDerivedReader(ctx, cipher, 32, salt, info)
		if err != nil {
			return "", fmt.Errorf("%s: %w", op, err)
		}
		edKey, _, err := ed25519.GenerateKey(reader)
		if err != nil {
			return "", fmt.Errorf("%s: unable to generate derived key: %w", op, ErrInvalidParameter)
		}
		n := copy(key[:], edKey)
		if n != 32 {
			return "", fmt.Errorf("%s: expected to copy 32 bytes and got: %d", op, n)
		}

	default:
		reader, err := NewDerivedReader(ctx, cipher, 32, salt, info)
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
