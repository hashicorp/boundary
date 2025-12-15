// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package checksum

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/internal/storage"
	"github.com/hashicorp/boundary/internal/util"
)

// ErrShortWrite represents an error where the number of written bytes between two writers do not match
var ErrShortWrite = errors.New("short write")

// ErrInvalidParameter represents an error where an invalid parameter value was provided
var ErrInvalidParameter = errors.New("invalid parameter")

const (
	sha256sumSep       = "  "
	sha256sumBinarySep = " *"
	sha256HexLength    = 64
)

// Sha256Sums is a map of file names with their corresponding SHA256SUM.
type Sha256Sums map[string][]byte

// LoadSha256Sums reads from an io.Reader to populate the Sha256Sums map The
// reader is expected to return the sums in a format that is compatible with
// sha256sum, that is each line should contain the hex encoded sum followed by
// a separator and then the file name. The separator should either be two
// spaces ("  ") or a space an asterisks (" *"). The former indicates a text
// file and the later a binary file. However, there is no difference between
// these for GNU systems. Therefore this also makes no distinction between the
// separators and checks for either.
//
// See: https://man7.org/linux/man-pages/man1/sha256sum.1.html
func LoadSha256Sums(r io.Reader) (Sha256Sums, error) {
	const op = "checksum.LoadSha256Sums"

	s := make(Sha256Sums)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var sum, file string
		var ok bool
		sum, file, ok = strings.Cut(scanner.Text(), sha256sumSep)
		if !ok {
			sum, file, ok = strings.Cut(scanner.Text(), sha256sumBinarySep)
		}
		if !ok {
			return nil, fmt.Errorf("%s: improperly formated line", op)
		}

		if len(sum) != sha256HexLength {
			return nil, fmt.Errorf("%s: improperly formated line", op)
		}

		if _, dup := s[file]; dup {
			return nil, fmt.Errorf("%s: duplicate file", op)
		}

		s[file] = []byte(sum)
	}

	return s, nil
}

// Sum returns the sum for the provided file, or an error if there is no sum.
func (s Sha256Sums) Sum(f string) ([]byte, error) {
	const op = "checksum.(Sha256Sums).Sum"

	sum, ok := s[f]
	if !ok {
		return nil, fmt.Errorf("%s: no sum for file %s", op, f)
	}

	return sum, nil
}

// Sha256SumWriter is used to write to a hash and produce a sum.
// It implements io.WriterCloser, io.StringWriter and a storage.Writer.
type Sha256SumWriter struct {
	l          sync.Mutex
	hash       hash.Hash
	underlying storage.Writer
}

// NewSha256SumWriter creates a new Sha256SumWriter
func NewSha256SumWriter(ctx context.Context, file storage.Writer, hash hash.Hash) (*Sha256SumWriter, error) {
	const op = "checksum.NewSha256SumWriter"
	if util.IsNil(file) {
		return nil, fmt.Errorf("%s: missing writer: %w", op, ErrInvalidParameter)
	}
	if util.IsNil(hash) {
		return nil, fmt.Errorf("%s: missing hash: %w", op, ErrInvalidParameter)
	}
	return &Sha256SumWriter{
		hash:       hash,
		underlying: file,
	}, nil
}

// Write will write the bytes to the hash. Implements the required io.Writer
// func.
func (w *Sha256SumWriter) Write(b []byte) (int, error) {
	const op = "checksum.(Sha256SumWriter).Write"
	w.l.Lock()
	defer w.l.Unlock()
	n, err := w.hash.Write(b)
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}
	m, err := w.underlying.Write(b)
	if err != nil {
		return m, fmt.Errorf("%s: %w", op, err)
	}
	if n != m {
		return m, ErrShortWrite
	}
	return n, nil
}

// WriteString will write the string to hash.
func (w *Sha256SumWriter) WriteString(s string) (int, error) {
	const op = "checksum.(Sha256SumWriter).WriteString"
	w.l.Lock()
	defer w.l.Unlock()
	n, err := w.hash.Write([]byte(s))
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}
	m, err := w.underlying.Write([]byte(s))
	if err != nil {
		return m, fmt.Errorf("%s: %w", op, err)
	}
	if n != m {
		return m, ErrShortWrite
	}
	return n, nil
}

// WriteAndClose will write the bytes to the hash and then will the Close
func (w *Sha256SumWriter) WriteAndClose(b []byte) (int, error) {
	const op = "checksum.(Sha256SumWriter).WriteAndClose"
	w.l.Lock()
	defer w.l.Unlock()
	n, err := w.hash.Write(b)
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}
	m, err := w.underlying.WriteAndClose(b)
	if err != nil {
		return m, fmt.Errorf("%s: %w", op, err)
	}
	if n != m {
		return m, ErrShortWrite
	}
	return n, nil
}

// Close checks to see if the Sha256SumWriter implements the optional io.Closer
// and if so, then Close() is called; otherwise this is a noop
func (w *Sha256SumWriter) Close() error {
	const op = "checksum.(Sha256SumWriter).Close"
	w.l.Lock()
	defer w.l.Unlock()
	var i interface{} = w.underlying
	if v, ok := i.(io.Closer); ok {
		if err := v.Close(); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// Sum will sum the hash.  Options supported: WithHexEncoding
func (w *Sha256SumWriter) Sum(_ context.Context, opt ...Option) ([]byte, error) {
	const op = "checksum.(Sha256SumWriter).Sum"
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
