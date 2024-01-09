// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Package checksum provides a wrapper to compute a checksum on a writable file
// while it is being written to, and record the final checksum when the file is
// closed.
package checksum

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/crypto"
)

const (
	// A line for a checksum that can be read by sha256sum.
	// Note that there are two spaces between the checksum and the file.
	checksumLine = "%s  %s\n"
)

var errInvalidParameter = errors.New("invalid parameter")

type writerFile interface {
	fs.File
	io.WriteCloser
	io.StringWriter
}

// File is a writable file that will compute its checksum while it is written
// to. When closed, it will write its checksum to the provided io.Writer.
// The checksum is written in a format so that it can be verified by sha256sum.
type File struct {
	// ctx is used to provide a context to other functions when implementing
	// std interfaces that to not take a context as an arg.
	ctx context.Context

	// Performs the checksuming, provides implementations for Write and
	// WriteString
	*crypto.Sha256SumWriter

	checksumWriter io.Writer

	underlying fs.File
}

// NewFile wraps the provided writerFile in a checksumed File. When the file is
// closed, its checksum will be written to cs.
func NewFile(ctx context.Context, f writerFile, cs io.Writer) (*File, error) {
	const op = "checksum.NewFile"

	switch {
	case is.Nil(f):
		return nil, fmt.Errorf("%s: missing writable file: %w", op, errInvalidParameter)
	case is.Nil(cs):
		return nil, fmt.Errorf("%s: missing checksum writer: %w", op, errInvalidParameter)
	}

	wrapped, err := crypto.NewSha256SumWriter(ctx, f)
	if err != nil {
		return nil, err
	}
	return &File{
		ctx:             ctx,
		checksumWriter:  cs,
		Sha256SumWriter: wrapped,
		underlying:      f,
	}, nil
}

// Stat returns the fs.FileInfo for the underlying fs.File.
func (f *File) Stat() (fs.FileInfo, error) {
	return f.underlying.Stat()
}

// Read reads from the underlying fs.File.
func (f *File) Read(b []byte) (int, error) {
	return f.underlying.Read(b)
}

// Close closes the Sha256SumWriter, computes the checksum and writes it to
// f.checksumWriter
func (f *File) Close() error {
	const op = "checksum.(File).Close"

	var closeErrors error

	// Call stat before closure; calling it after results in an err
	s, err := f.Stat()
	if err != nil {
		closeErrors = errors.Join(closeErrors, fmt.Errorf("%s: %w", op, err))
		return closeErrors
	}

	// f.Sha256SumWriter will close f.underlying
	if err := f.Sha256SumWriter.Close(); err != nil {
		closeErrors = errors.Join(closeErrors, fmt.Errorf("%s: %w", op, err))
	}

	sum, err := f.Sha256SumWriter.Sum(f.ctx, crypto.WithHexEncoding(true))
	if err != nil {
		closeErrors = errors.Join(closeErrors, fmt.Errorf("%s: %w", op, err))
		return closeErrors
	}

	if _, err := f.checksumWriter.Write([]byte(fmt.Sprintf(checksumLine, sum, s.Name()))); err != nil {
		closeErrors = errors.Join(closeErrors, fmt.Errorf("%s: %w", op, err))
	}
	return closeErrors
}

var _ writerFile = (*File)(nil)
