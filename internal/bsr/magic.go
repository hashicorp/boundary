// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/bsr/internal/is"
)

const (
	// Magic is the magic string / magic number / file signature used to
	// identify a BSR data file.
	//
	// See: https://en.wikipedia.org/wiki/File_format#Magic_number
	Magic magic = magic("\x89BSR\r\n\x1a\n")

	magicSize = len(Magic)
)

type magic string

// Bytes returns the magic as a []byte.
func (s magic) Bytes() []byte {
	return []byte(s)
}

// ReadMagic attempts to read the magic string from the given io.Reader.
// If it is unable to read enough bytes, or if the magic string does not match
// an error is returned.
func ReadMagic(r io.Reader) error {
	const op = "bsr.ReadMagic"

	if is.Nil(r) {
		return fmt.Errorf("%s: reader is nil: %w", op, ErrInvalidParameter)
	}

	m := make([]byte, magicSize)
	_, err := io.ReadAtLeast(r, m, magicSize)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if len(m) < magicSize || magic(m[:magicSize]) != Magic {
		return fmt.Errorf("%s: %w", op, ErrInvalidMagic)
	}
	return nil
}
