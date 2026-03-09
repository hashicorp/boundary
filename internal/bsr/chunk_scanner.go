// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/crypto"
)

// ChunkScanner can be used to read a Chunk at a time.
type ChunkScanner struct {
	checksum     []byte
	reader       *crypto.Sha256SumReader
	chunkDecoder *ChunkDecoder
}

// NewChunkScanner creates a ChunkScanner. The scanner will calculate a rolling
// sha256sum of all of the chunks that have been read.
// Supports the following options:
//   - WithSha256Sum: This is used to provide an expected sha256sum. Once the
//     scanner encounters an END chunk or an io.EOF error, it will compare the
//     calculated sha256sum against this sum. If the sums do not match, ErrChecksum
//     will be returned.
//
// Other options are passed through to the ChunkDecoder used by the scanner.
func NewChunkScanner(ctx context.Context, r io.Reader, options ...Option) (*ChunkScanner, error) {
	const op = "bsr.NewChunkScanner"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: reader is nil: %w", op, ErrInvalidParameter)
	}

	sha256Reader, err := crypto.NewSha256SumReader(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := ReadMagic(sha256Reader); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	cd, err := NewChunkDecoder(ctx, sha256Reader, options...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	opts := getOpts(options...)

	return &ChunkScanner{
		checksum:     opts.withSha256Sum,
		reader:       sha256Reader,
		chunkDecoder: cd,
	}, nil
}

// Scan reads the next Chunk from the reader.
// If the scanner was created using WithSha256Sum, the calculated sum will
// be compared to the provided sum when the scanner encounters either an END
// Chunk, or an io.EOF error. If the sums do not match, ErrChecksum will be
// returned.
func (cs *ChunkScanner) Scan(ctx context.Context) (Chunk, error) {
	const op = "bsr.(ChunkScanner).Scan"

	c, err := cs.chunkDecoder.Decode(ctx)
	if (err == io.EOF ||
		(err == nil && c.GetType() == ChunkEnd)) &&
		len(cs.checksum) > 0 {
		sum, err := cs.Sum(ctx)
		if err != nil {
			return c, fmt.Errorf("%s: %w", op, err)
		}

		if string(cs.checksum) != string(sum) {
			return c, fmt.Errorf("%s: %w", op, ErrChecksum)
		}
	}

	return c, err
}

// Close closes the scanner's reader.
func (cs *ChunkScanner) Close() error {
	return cs.reader.Close()
}

// Sum returns a hex encoded sha256sum of all of the chunks that have been
// scanned.
func (cs *ChunkScanner) Sum(ctx context.Context) ([]byte, error) {
	return cs.reader.Sum(ctx, crypto.WithHexEncoding(true))
}

// ChunkReadFunc is a function that can be used by ChunkWalk to process a Chunk.
type ChunkReadFunc func(ctx context.Context, c Chunk) error

// ChunkWalk will step through the chunks returned by the ChunkScanner and call
// the provided ChunkReadFunc f for each. If f returns an error or a non io.EOF
// error is returned from the scanner the walk will terminate early. Otherwise
// the walk will terminate once io.EOF is reached.
func ChunkWalk(ctx context.Context, s *ChunkScanner, f ChunkReadFunc) error {
	const op = "bsr.ChunkWalk"

	for {
		c, err := s.Scan(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}

		if ferr := f(ctx, c); ferr != nil {
			return fmt.Errorf("%s: %w", op, ferr)
		}
	}
}
