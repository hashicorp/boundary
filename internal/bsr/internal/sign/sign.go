// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package sign provides wrappers to compute a signature of data written to an
// io.Writer
package sign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync"

	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
)

var errInvalidParameter = errors.New("invalid parameter")

// Writer is a wrapper that will compute a signature of all the data
// written to its writer.
type Writer struct {
	keys *kms.Keys

	buf *bytes.Buffer
	w   io.Writer
	tee io.Writer

	// This lock protects the buf and w variables defined in this Writer struct as a
	// consequence of these variables both being written to at the same time using tee
	l sync.Mutex
}

// NewWriter returns a Writer that wraps an io.Writer.
func NewWriter(_ context.Context, w io.Writer, keys *kms.Keys) (*Writer, error) {
	const op = "sign.NewWriter"
	switch {
	case is.Nil(w):
		return nil, fmt.Errorf("%s: missing sign writer: %w", op, errInvalidParameter)
	case is.Nil(keys):
		return nil, fmt.Errorf("%s: missing keys: %w", op, errInvalidParameter)
	}

	var buf bytes.Buffer
	tee := io.MultiWriter(w, &buf)
	return &Writer{
		buf:  &buf,
		tee:  tee,
		keys: keys,
		w:    w,
	}, nil
}

func (w *Writer) Write(b []byte) (int, error) {
	w.l.Lock()
	defer w.l.Unlock()
	return w.tee.Write(b)
}

// WriteString implements the io.StringWriter WriteString method.
func (w *Writer) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

// Close implements the io.Closer method.
func (w *Writer) Close() error {
	const op = "sign.(Writer).Close"
	w.l.Lock()
	defer w.l.Unlock()
	var i interface{} = w.w
	v, ok := i.(io.WriteCloser)
	if ok {
		if err := v.Close(); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// Sign returns the signature of the data written to the writer.
func (w *Writer) Sign(ctx context.Context) (*wrapping.SigInfo, error) {
	w.l.Lock()
	defer w.l.Unlock()
	sig, err := w.keys.SignWithPrivKey(ctx, w.buf.Bytes())
	if err != nil {
		return nil, err
	}
	return sig, nil
}

type writerFile interface {
	fs.File
	io.WriteCloser
	io.StringWriter
}

// File is a writable file that will compute it's signature while it is written
// to. When closed, it will write the signature to the provided io.Writer.
type File struct {
	ctx             context.Context
	signatureWriter io.Writer

	// Performs the signing, and provides implementations for Write and
	// WriteString.
	*Writer

	underlying fs.File
}

// Stat returns the fs.FileInfo for the underlying fs.File.
func (f *File) Stat() (fs.FileInfo, error) {
	return f.underlying.Stat()
}

// Read reads from the underlying fs.File.
func (f *File) Read(b []byte) (int, error) {
	return f.underlying.Read(b)
}

// NewFile wraps the provided writerFile in a signed File. When the file is
// closed, its signature is written to w.
func NewFile(ctx context.Context, f writerFile, w io.Writer, keys *kms.Keys) (*File, error) {
	const op = "sign.NewFile"

	switch {
	case is.Nil(f):
		return nil, fmt.Errorf("%s: missing writable file: %w", op, errInvalidParameter)
	case is.Nil(w):
		return nil, fmt.Errorf("%s: missing sign writer: %w", op, errInvalidParameter)
	case is.Nil(keys):
		return nil, fmt.Errorf("%s: missing keys: %w", op, errInvalidParameter)
	}

	sw, err := NewWriter(ctx, f, keys)
	if err != nil {
		return nil, err
	}
	return &File{
		ctx:             ctx,
		signatureWriter: w,
		Writer:          sw,
		underlying:      f,
	}, nil
}

// Close closes the wrapped writer and writes the SigInfo to f.signatureWriter.
func (f *File) Close() error {
	const op = "sign.(File).Close"

	var closeErrors error
	if err := f.Writer.Close(); err != nil {
		closeErrors = errors.Join(closeErrors, fmt.Errorf("%s: %w", op, err))
	}

	sig, err := f.Writer.Sign(f.ctx)
	if err != nil {
		closeErrors = errors.Join(closeErrors, fmt.Errorf("%s: %w", op, err))
		return closeErrors
	}

	b, err := proto.Marshal(sig)
	if err != nil {
		closeErrors = errors.Join(closeErrors, fmt.Errorf("%s: %w", op, err))
		return closeErrors
	}

	if _, err := f.signatureWriter.Write(b); err != nil {
		closeErrors = errors.Join(closeErrors, fmt.Errorf("%s: %w", op, err))
	}

	return closeErrors
}

var _ writerFile = (*File)(nil)
