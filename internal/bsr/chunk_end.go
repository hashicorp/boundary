// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import "context"

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
	const op = "bsr.NewHeader"

	bc, err := NewBaseChunk(ctx, p, d, t, ChunkEnd)
	if err != nil {
		return nil, err
	}

	return &EndChunk{
		BaseChunk: bc,
	}, nil
}
