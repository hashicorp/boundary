// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"golang.org/x/crypto/hkdf"
)

// DerivedReader returns a reader from which keys can be read, using the
// given wrapper, reader length limit, salt and context info. Salt and info can
// be nil.
//
// Example:
//	reader, _ := crypto.NewDerivedReader(wrapper, userId, jobId)
// 	key := ed25519.GenerateKey(reader)
func NewDerivedReader(ctx context.Context, wrapper wrapping.Wrapper, lenLimit int64, opt ...wrapping.Option) (*io.LimitedReader, error) {
	const (
		op     = "reader.NewDerivedReader"
		minLen = 20
	)
	if wrapper == nil {
		return nil, fmt.Errorf("%s: missing wrapper: %w", op, wrapping.ErrInvalidParameter)
	}
	if lenLimit < minLen {
		return nil, fmt.Errorf("%s: lenLimit must be >= %d: %w", op, minLen, wrapping.ErrInvalidParameter)
	}
	biter, ok := wrapper.(wrapping.KeyExporter)
	if !ok {
		return nil, fmt.Errorf("%s: wrapper does not implement required KeyBytes interface: %w", op, wrapping.ErrInvalidParameter)
	}
	b, err := biter.KeyBytes(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to get current key bytes: %w", op, err)
	}
	if b == nil {
		return nil, fmt.Errorf("%s: wrapper missing bytes: %w", op, wrapping.ErrInvalidParameter)
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to get options %w", op, err)
	}
	reader := hkdf.New(sha256.New, b, opts.withSalt, opts.withInfo)
	return &io.LimitedReader{
		R: reader,
		N: lenLimit,
	}, nil
}
