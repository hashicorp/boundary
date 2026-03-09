// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr/internal/is"
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

// DecodeHeader will decode a Header chunk.
func DecodeHeader(_ context.Context, bc *BaseChunk, data []byte) (Chunk, error) {
	const op = "bsr.DecodeHeader"

	if is.Nil(bc) {
		return nil, fmt.Errorf("%s: nil base chunk: %w", op, ErrInvalidParameter)
	}
	if bc.Type != ChunkHeader {
		return nil, fmt.Errorf("%s: invalid chunk type %s", op, bc.Type)
	}

	if uint32(len(data)) < compressionSize+encryptionSize {
		return nil, fmt.Errorf("%s: not enough data", op)
	}

	h := &HeaderChunk{BaseChunk: bc}
	h.Compression, data = Compression(data[:compressionSize][0]), data[compressionSize:]
	h.Encryption, data = Encryption(data[:encryptionSize][0]), data[encryptionSize:]
	h.SessionId = string(data)

	return h, nil
}
