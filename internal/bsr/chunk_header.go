// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

import (
	"context"
	"fmt"
)

// HeaderChunk is the first chunk in a BSR data file.
// A HeaderChunk in a bsr data file is represented as:
//
//	uint32 length      4 bytes
//	uint32 protocol    4 bytes
//	uint32 chunk_type  4 bytes
//	uint8  direction   1 byte
//	timest timestamp  12 bytes
//	uint8  compression 1 byte
//	uint8  encryption  1 byte
//	       session_id variable
//	uint32 crc         4 bytes
type HeaderChunk struct {
	*BaseChunk
	Compression Compression
	Encryption  Encryption
	SessionId   string
}

// MarshalData serializes a HeaderChunk.
func (h *HeaderChunk) MarshalData(_ context.Context) ([]byte, error) {
	b := make([]byte, 0, len(h.SessionId)+compressionSize+encryptionSize)
	b = append(b, byte(h.Compression))
	b = append(b, byte(h.Encryption))
	b = append(b, []byte(h.SessionId)...)
	return b, nil
}

// NewHeader creates a HeaderChunk.
func NewHeader(ctx context.Context, p Protocol, d Direction, t *Timestamp, c Compression, e Encryption, sessionId string) (*HeaderChunk, error) {
	const op = "bsr.NewHeader"

	bc, err := NewBaseChunk(ctx, p, d, t, ChunkHeader)
	if err != nil {
		return nil, err
	}

	if !ValidCompression(c) {
		return nil, fmt.Errorf("%s: invalid compression: %w", op, ErrInvalidParameter)
	}

	if !ValidEncryption(e) {
		return nil, fmt.Errorf("%s: invalid encryption: %w", op, ErrInvalidParameter)
	}

	return &HeaderChunk{
		BaseChunk:   bc,
		Compression: c,
		Encryption:  e,
		SessionId:   sessionId,
	}, nil
}
