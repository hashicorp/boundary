// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"

	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	"github.com/hashicorp/boundary/internal/bsr/kms"
)

// DecodeChunkFunc is a function that given a BaseChunk and the data portion
// of a chunk, will decode the data into a Chunk.
type DecodeChunkFunc func(ctx context.Context, bc *BaseChunk, data []byte) (Chunk, error)

type decodeFuncsRegistry map[Protocol]map[ChunkType]DecodeChunkFunc

func (r decodeFuncsRegistry) Get(p Protocol, t ChunkType) (DecodeChunkFunc, bool) {
	switch t {
	case ChunkHeader:
		return DecodeHeader, true
	case ChunkEnd:
		return DecodeEnd, true
	default:
		protocol, ok := r[p]
		if !ok {
			return nil, false
		}
		df, ok := protocol[t]
		return df, ok
	}
}

var chunkTypes decodeFuncsRegistry

// RegisterChunkType registers a DecodeChunkFunc for the given Protocol and
// ChunkType. A given Protocol and ChunkType can only have one decode function
// registered.
func RegisterChunkType(p Protocol, t ChunkType, df DecodeChunkFunc) error {
	const op = "bsr.RegisterChunkType"

	if chunkTypes == nil {
		chunkTypes = make(map[Protocol]map[ChunkType]DecodeChunkFunc)
	}

	protocol, ok := chunkTypes[p]
	if !ok {
		protocol = make(map[ChunkType]DecodeChunkFunc)
	}

	_, ok = protocol[t]
	if ok {
		return fmt.Errorf("%s: %s %s: %w", op, p, t, ErrAlreadyRegistered)
	}
	protocol[t] = df
	chunkTypes[p] = protocol
	return nil
}

// ChunkDecoder is used to decode the data read from an io.Reader into Chunks.
type ChunkDecoder struct {
	r           io.Reader
	compression Compression
	encryption  Encryption

	keys *kms.Keys
}

// NewChunkDecoder creates a ChunkDecoder that can decode the data read from
// the given io.Reader. Supports the WithKeys option which will be used when
// support for encrypted chunks is added.
func NewChunkDecoder(_ context.Context, r io.Reader, options ...Option) (*ChunkDecoder, error) {
	const op = "bsr.NewChunkDecoder"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: reader cannot be nil: %w", op, ErrInvalidParameter)
	}

	opts := getOpts(options...)

	return &ChunkDecoder{
		r:           r,
		compression: NoCompression,
		encryption:  NoEncryption,
		keys:        opts.withKeys,
	}, nil
}

// Decode will read from the io.Reader and return the next Chunk that it
// decodes.  If the io.Reader reaches EOF, Decode will return an error of
// io.EOF. Note that this is not a wrapped error so it can be checked for with
// err == io.EOF like with most io.Readers. If there is an unexpected error
// while decoding, such as an unsupported chunk type or corrupted data, an
// ErrChunkDecode error will be returned. This will be a wrapped error and
// should be checked for with errors.Is.
func (d *ChunkDecoder) Decode(ctx context.Context) (Chunk, error) {
	const op = "bsr.(ChunkDecoder).Decode"

	var b *BaseChunk

	buf := make([]byte, chunkBaseSize)
	crcBuf := make([]byte, crcSize)

	_, err := io.ReadAtLeast(d.r, buf, chunkBaseSize)
	if err != nil {
		if err == io.EOF || errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrChunkDecode)
	}

	var length uint32
	var protocol Protocol
	var chunkType ChunkType
	var direction Direction

	crc := crc32.NewIEEE()

	length, buf = binary.BigEndian.Uint32(buf[:lengthSize]), buf[lengthSize:]
	if length > MaxChunkDataLength {
		return nil, fmt.Errorf("%s: chunk length %d exceeds max chunk length of %d: %w", op, length, MaxChunkDataLength, ErrChunkDecode)
	}
	databuf := make([]byte, length)
	_, err = io.ReadAtLeast(d.r, databuf, int(length))
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("%s: %w: missing data: %w", op, err, ErrChunkDecode)
	}
	crc.Write(append(buf, databuf...))

	_, err = io.ReadAtLeast(d.r, crcBuf, crcSize)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("%s: %w: missing crc: %w", op, err, ErrChunkDecode)
	}
	if crc.Sum32() != binary.BigEndian.Uint32(crcBuf) {
		log.Printf("%x", crc.Sum32())
		return nil, fmt.Errorf("%s: chunk crc did not match: %w", op, ErrChunkDecode)
	}

	protocol, buf = Protocol(string(buf[:protocolSize])), buf[protocolSize:]
	chunkType, buf = ChunkType(string(buf[:chunkTypeSize])), buf[chunkTypeSize:]
	direction, buf = Direction(buf[:directionSize][0]), buf[directionSize:]

	timestamp, err := decodeTimestamp(buf[:timestampSize])
	if err != nil {
		return nil, fmt.Errorf("%s: error parsing timestamp: %w: %w", op, err, ErrChunkDecode)
	}
	buf = buf[timestampSize:]
	if len(buf) != 0 {
		return nil, fmt.Errorf("%s: extra data in chunk: %w", op, ErrChunkDecode)
	}

	b, err = NewBaseChunk(ctx, protocol, direction, timestamp, chunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrChunkDecode)
	}

	decompressBuf := bytes.NewBuffer(databuf)
	var decompressor io.ReadCloser
	switch chunkType {
	// HEAD and END are never compressed
	case ChunkHeader, ChunkEnd:
		decompressor = newNullCompressionReader(decompressBuf)
	default:
		switch d.compression {
		case GzipCompression:
			decompressor, err = gzip.NewReader(decompressBuf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w: %w", op, err, ErrChunkDecode)
			}
		default:
			decompressor = newNullCompressionReader(decompressBuf)
		}
	}

	// Decompressed chunk data should not go beyond MaxChunkDataLength/ prevent allocations beyond this limit
	limitedDecompressionReader := io.LimitReader(decompressor, MaxChunkDataLength)
	decompressed, err := io.ReadAll(limitedDecompressionReader)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrChunkDecode)
	}

	df, ok := chunkTypes.Get(b.Protocol, b.Type)
	if !ok {
		return nil, fmt.Errorf("%s: unsupported chunk type %s for protocol %s: %w", op, b.Type, b.Protocol, ErrChunkDecode)
	}

	c, err := df(ctx, b, decompressed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", op, err, ErrChunkDecode)
	}

	switch cc := c.(type) {
	case *HeaderChunk:
		d.compression = cc.Compression
		d.encryption = cc.Encryption
	}

	return c, nil
}
