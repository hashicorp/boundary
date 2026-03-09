// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"sync"

	"github.com/hashicorp/boundary/internal/storage"
)

type encodeCache struct {
	crced    [crcDataSize]byte
	compress *bytes.Buffer
	crc      hash.Hash32
}

// Reset clears all existing values in the cache item, preventing dirty reads.
// This function should be called when retrieving items from the encodeCachePool.
func (e *encodeCache) Reset() {
	e.compress.Reset()
	e.crc.Reset()
}

// encodeCachePool is to cache allocated but unused items for later reuse, relieving pressure on the garbage collector.
// encodeCachePool is safe for use by multiple goroutines simultaneously.
// encodeCachePool must not be copied after first use.
var encodeCachePool = &sync.Pool{
	New: func() interface{} {
		return &encodeCache{
			compress: bytes.NewBuffer(make([]byte, 0, 1024)),
			crc:      crc32.NewIEEE(),
		}
	},
}

// ChunkEncoder will encode a chunk and write it to the writer.
// It will compress the chunk data based on the compression.
type ChunkEncoder struct {
	w           storage.Writer
	compression Compression
	encryption  Encryption
}

// NewChunkEncoder creates a ChunkEncoder.
func NewChunkEncoder(ctx context.Context, w storage.Writer, c Compression, e Encryption) (*ChunkEncoder, error) {
	const op = "bsr.NewChunkEncoder"

	if w == nil {
		return nil, fmt.Errorf("%s: writer cannot be nil: %w", op, ErrInvalidParameter)
	}

	if !ValidCompression(c) {
		return nil, fmt.Errorf("%s: invalid compression: %w", op, ErrInvalidParameter)
	}

	if !ValidEncryption(e) {
		return nil, fmt.Errorf("%s: invalid encryption: %w", op, ErrInvalidParameter)
	}

	return &ChunkEncoder{
		w:           w,
		compression: c,
		encryption:  e,
	}, nil
}

// Encode serializes a Chunk and writes it with the encoder's writer.
func (e ChunkEncoder) Encode(ctx context.Context, c Chunk) (int, error) {
	encode := encodeCachePool.Get().(*encodeCache)
	encode.Reset()
	defer encodeCachePool.Put(encode)

	data, err := c.MarshalData(ctx)
	if err != nil {
		return 0, err
	}

	var compressor io.WriteCloser
	switch c.GetType() {
	// Header should not be compressed since we need to read it prior to knowing
	// what compression was used to check the compression bit.
	// End should not be compressed since it has no data and compressing an empty
	// byte slice just adds data in the form of the compression magic strings.
	case ChunkHeader, ChunkEnd:
		compressor = newNullCompressionWriter(encode.compress)
	default:
		switch e.compression {
		case GzipCompression:
			compressor = gzip.NewWriter(encode.compress)
		default:
			compressor = newNullCompressionWriter(encode.compress)
		}
	}

	if _, err := compressor.Write(data); err != nil {
		return 0, err
	}
	err = compressor.Close()
	if err != nil {
		return 0, err
	}
	length := encode.compress.Len()

	copy(encode.crced[0:], []byte(c.GetProtocol()))
	copy(encode.crced[protocolSize:], []byte(c.GetType()))
	encode.crced[protocolSize+chunkTypeSize] = byte(c.GetDirection())
	copy(encode.crced[protocolSize+chunkTypeSize+directionSize:], c.GetTimestamp().marshal())

	if _, err := encode.crc.Write(encode.crced[0:]); err != nil {
		return 0, err
	}
	if _, err := encode.crc.Write(encode.compress.Bytes()); err != nil {
		return 0, err
	}
	sum := encode.crc.Sum32()

	encodedChunk := make([]byte, chunkBaseSize+length+crcSize)
	binary.BigEndian.PutUint32(encodedChunk[0:], uint32(length))
	copy(encodedChunk[lengthSize:], encode.crced[0:])
	copy(encodedChunk[chunkBaseSize:], encode.compress.Bytes())
	binary.BigEndian.PutUint32(encodedChunk[chunkBaseSize+length:], sum)

	if c.GetType() == ChunkEnd {
		return e.w.WriteAndClose(encodedChunk)
	}

	return e.w.Write(encodedChunk)
}
