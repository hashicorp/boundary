// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"fmt"
)

// sizes
const (
	lengthSize    = 4
	protocolSize  = 4
	chunkTypeSize = 4
	directionSize = 1

	crcDataSize   = protocolSize + chunkTypeSize + directionSize + timestampSize
	chunkBaseSize = lengthSize + crcDataSize
	crcSize       = 4

	// MaxChunkDataLength sets an upper bound on BSR chunk lengths
	// Default to 64MB, as this is the limit for protobufs, which back our chunks
	// TODO: Should this be configurable as an option?
	MaxChunkDataLength = 64 * 100 * 1000
)

// Chunk Types
const (
	ChunkHeader ChunkType = "HEAD"
	ChunkEnd    ChunkType = "DONE"
)

// ChunkType identifies the type of a chunk.
type ChunkType string

// ValidChunkType checks ifa given ChunkType is valid.
func ValidChunkType(c ChunkType) bool {
	return len(c) <= chunkTypeSize
}

// Chunk is a section of a bsr data file.
type Chunk interface {
	// GetLength returns the length of the chunk data.
	GetLength() uint32
	// GetProtocol returns the protocol of the recorded data.
	GetProtocol() Protocol
	// GetType returns the chunk type.
	GetType() ChunkType
	// GetDirection returns the direction of the data in the chunk.
	GetDirection() Direction
	// GetTimestamp returns the timestamp of a Chunk.
	GetTimestamp() *Timestamp

	// MarshalData serializes the data portion of a chunk.
	MarshalData(context.Context) ([]byte, error)
}

// BaseChunk contains the common fields of all chunk types.
type BaseChunk struct {
	Protocol  Protocol
	Direction Direction
	Timestamp *Timestamp
	Type      ChunkType

	length uint32
}

// NewBaseChunk creates a BaseChunk.
func NewBaseChunk(ctx context.Context, p Protocol, d Direction, t *Timestamp, typ ChunkType) (*BaseChunk, error) {
	const op = "bsr.NewBaseChunk"
	if !ValidProtocol(p) {
		return nil, fmt.Errorf("%s: protocol name cannot be greater than 4 characters: %w", op, ErrInvalidParameter)
	}
	if !ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, ErrInvalidParameter)
	}
	if t == nil {
		return nil, fmt.Errorf("%s: timestamp must not be nil: %w", op, ErrInvalidParameter)
	}
	if !ValidChunkType(typ) {
		return nil, fmt.Errorf("%s: chunk type cannot be greater than 4 characters: %w", op, ErrInvalidParameter)
	}

	return &BaseChunk{
		Protocol:  p,
		Direction: d,
		Timestamp: t,
		Type:      typ,
	}, nil
}

// GetLength returns the length of the chunk data.
func (b *BaseChunk) GetLength() uint32 {
	return b.length
}

// GetProtocol returns the protocol of the recorded data.
func (b *BaseChunk) GetProtocol() Protocol {
	return b.Protocol
}

// GetType returns the chunk type.
func (b *BaseChunk) GetType() ChunkType {
	return b.Type
}

// GetDirection returns the direction of the data in the chunk.
func (b *BaseChunk) GetDirection() Direction {
	return b.Direction
}

// GetTimestamp returns the timestamp of a Chunk.
func (b *BaseChunk) GetTimestamp() *Timestamp {
	return b.Timestamp
}
