// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"sync"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// Sha256Sum computes SHA256 message digest. Options supported: WithHexEncoding
// (which is compatible/comparable with GNU sha256sum's output)
func Sha256Sum(ctx context.Context, r io.Reader, opt ...wrapping.Option) ([]byte, error) {
	const op = "crypto.Sha256Sum"
	switch {
	case isNil(r):
		return nil, fmt.Errorf("%s: missing reader: %w", op, wrapping.ErrInvalidParameter)
	}

	hasher := sha256.New()

	if _, err := io.Copy(hasher, r); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	hash := hasher.Sum(nil)
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if opts.WithHexEncoding {
		encodedHex := hex.EncodeToString(hash[:])
		return []byte(encodedHex), nil
	}
	return hash, nil
}

// Sha256SumWriter provides multi-writer which will be used to write to a
// hash and produce a sum.  It implements io.WriterCloser and io.StringWriter.
type Sha256SumWriter struct {
	l    sync.Mutex
	hash hash.Hash
	tee  io.Writer
	w    io.Writer
}

// NewSha256SumWriter creates a new Sha256SumWriter
func NewSha256SumWriter(ctx context.Context, w io.Writer) (*Sha256SumWriter, error) {
	const op = "crypto.NewSha256SumWriter"
	switch {
	case isNil(w):
		return nil, fmt.Errorf("%s: missing writer: %w", op, wrapping.ErrInvalidParameter)
	}
	h := sha256.New()
	tee := io.MultiWriter(w, h)
	return &Sha256SumWriter{
		hash: h,
		tee:  tee,
		w:    w,
	}, nil
}

// Write will write the bytes to the hash. Implements the required io.Writer
// func.
func (w *Sha256SumWriter) Write(b []byte) (int, error) {
	const op = "crypto.(Sha256SumWriter).Write"
	w.l.Lock()
	defer w.l.Unlock()
	n, err := w.tee.Write(b)
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// WriteString will write the string to hash.
func (w *Sha256SumWriter) WriteString(s string) (int, error) {
	const op = "crypto.(Sha256SumWriter).WriteString"
	n, err := w.Write([]byte(s))
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// Close checks to see if the Sha256SumWriter implements the optional io.Closer
// and if so, then Close() is called; otherwise this is a noop
func (w *Sha256SumWriter) Close() error {
	const op = "crypto.(Sha256SumWriter).Close"
	var i interface{} = w.w
	if v, ok := i.(io.Closer); ok {
		if err := v.Close(); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// Sum will sum the hash.  Options supported: WithHexEncoding
func (w *Sha256SumWriter) Sum(_ context.Context, opt ...wrapping.Option) ([]byte, error) {
	const op = "crypto.(Sha256SumWriter).Sum"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	w.l.Lock()
	defer w.l.Unlock()
	h := w.hash.Sum(nil)
	switch {
	case opts.WithHexEncoding:
		encodedHex := hex.EncodeToString(h[:])
		return []byte(encodedHex), nil
	default:
		return h, nil
	}
}

// Sha256SumReader provides an io.Reader which can be used to calculate a sum
// while reading a file. It implements io.ReaderCloser.
type Sha256SumReader struct {
	l    sync.Mutex
	hash hash.Hash
	tee  io.Reader
	r    io.Reader
}

// NewSha256SumReader creates a new Sha256Reader.
func NewSha256SumReader(_ context.Context, r io.Reader) (*Sha256SumReader, error) {
	const op = "crypto.NewSha256SumReader"
	switch {
	case isNil(r):
		return nil, fmt.Errorf("%s: missing reader: %w", op, wrapping.ErrInvalidParameter)
	}
	h := sha256.New()
	tee := io.TeeReader(r, h)
	return &Sha256SumReader{
		hash: h,
		tee:  tee,
		r:    r,
	}, nil
}

func (r *Sha256SumReader) Read(b []byte) (int, error) {
	const op = "crypto.(Sha256SumReader).Read"
	r.l.Lock()
	defer r.l.Unlock()
	n, err := r.tee.Read(b)
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// Close checks to see if the Sha256SumReader's io.Reader implements the
// optional io.Closer and if so, then Close() is called; otherwise this is a
// noop
func (r *Sha256SumReader) Close() error {
	const op = "crypto.(Sha256SumReader).Close"
	var i interface{} = r.r
	if v, ok := i.(io.Closer); ok {
		if err := v.Close(); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// Sum will sum the hash.  Options supported: WithHexEncoding
func (r *Sha256SumReader) Sum(_ context.Context, opt ...wrapping.Option) ([]byte, error) {
	const op = "crypto.(Sha256SumReader).Sum"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	r.l.Lock()
	defer r.l.Unlock()
	h := r.hash.Sum(nil)
	switch {
	case opts.WithHexEncoding:
		encodedHex := hex.EncodeToString(h[:])
		return []byte(encodedHex), nil
	default:
		return h, nil
	}
}
