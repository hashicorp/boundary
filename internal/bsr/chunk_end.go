// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr/internal/is"
)

// EndChunk identifies the end of the chunks in a BSR data file.
// An EndChunk in a bsr data file is represented as:
//
//	uint32 length      4 bytes
//	uint32 protocol    4 bytes
//	uint32 chunk_type  4 bytes
//	uint8  direction   1 byte
//	timest timestamp  12 bytes
//	       data        0 bytes
//	uint32 crc         4 bytes
type EndChunk struct {
	*BaseChunk
}

// MarshalData returns an empty byte slice.
func (c *EndChunk) MarshalData(_ context.Context) ([]byte, error) {
	return nil, nil
}

// NewEnd creates an EndChunk.
func NewEnd(ctx context.Context, p Protocol, d Direction, t *Timestamp) (*EndChunk, error) {
	const op = "bsr.NewEnd"

	bc, err := NewBaseChunk(ctx, p, d, t, ChunkEnd)
	if err != nil {
		return nil, err
	}

	return &EndChunk{
		BaseChunk: bc,
	}, nil
}

// DecodeEnd will decode an EndChunk.
func DecodeEnd(_ context.Context, bc *BaseChunk, data []byte) (Chunk, error) {
	const op = "bsr.DecodeEnd"

	if is.Nil(bc) {
		return nil, fmt.Errorf("%s: nil base chunk: %w", op, ErrInvalidParameter)
	}
	if bc.Type != ChunkEnd {
		return nil, fmt.Errorf("%s: invalid chunk type %s", op, bc.Type)
	}
	if len(data) != 0 {
		return nil, fmt.Errorf("%s: %w", op, ErrEndChunkNotEmpty)
	}
	return &EndChunk{BaseChunk: bc}, nil
}
