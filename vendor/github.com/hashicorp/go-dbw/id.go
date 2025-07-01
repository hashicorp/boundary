// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/base62"
	"golang.org/x/crypto/blake2b"
)

// NewId creates a new random base62 ID with the provided prefix with an
// underscore delimiter
func NewId(prefix string, opt ...Option) (string, error) {
	const op = "dbw.NewId"
	if prefix == "" {
		return "", fmt.Errorf("%s: missing prefix: %w", op, ErrInvalidParameter)
	}
	var publicId string
	var err error
	opts := GetOpts(opt...)
	if len(opts.WithPrngValues) > 0 {
		sum := blake2b.Sum256([]byte(strings.Join(opts.WithPrngValues, "|")))
		reader := bytes.NewReader(sum[0:])
		publicId, err = base62.RandomWithReader(10, reader)
	} else {
		publicId, err = base62.Random(10)
	}
	if err != nil {
		return "", fmt.Errorf("%s: unable to generate id: %w", op, ErrInternal)
	}
	return fmt.Sprintf("%s_%s", prefix, publicId), nil
}
