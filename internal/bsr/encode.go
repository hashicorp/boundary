// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package bsr

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

// ChunkEncoder will encode a chunk and write it to the writer.
// It will compress the chunk data based on the compression.
type ChunkEncoder struct {
	w           io.Writer
	compression Compression
	encryption  Encryption
}

// NewChunkEncoder creates a ChunkEncoder.
func NewChunkEncoder(ctx context.Context, w io.Writer, c Compression, e Encryption) (*ChunkEncoder, error) {
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
	data, err := c.MarshalData(ctx)
	if err != nil {
		return 0, err
	}

	var buf bytes.Buffer
	var compressor io.WriteCloser
	switch c.GetType() {
	// Header should not be compressed since we need to read it prior to knowing
	// what compression was used to check the compression bit.
	// End should not be compressed since it has no data and compressing an empty
	// byte slice just adds data in the form of the compression magic strings.
	case ChunkHeader, ChunkEnd:
		compressor = newNullCompressionWriter(&buf)
	default:
		switch e.compression {
		case GzipCompression:
			compressor = gzip.NewWriter(&buf)
		default:
			compressor = newNullCompressionWriter(&buf)
		}
	}

	if _, err := compressor.Write(data); err != nil {
		return 0, err
	}
	err = compressor.Close()
	if err != nil {
		return 0, err
	}
	length := buf.Len()

	t := c.GetTimestamp().marshal()

	// calculate CRC for protocol+type+dir+timestamp+data
	crced := make([]byte, 0, chunkBaseSize+length)
	crced = append(crced, c.GetProtocol()...)
	crced = append(crced, c.GetType()...)
	crced = append(crced, byte(c.GetDirection()))
	crced = append(crced, t...)
	crced = append(crced, buf.Bytes()...)

	crc := crc32.NewIEEE()
	_, err = crc.Write(crced)
	if err != nil {
		return 0, err
	}

	d := make([]byte, 0, chunkBaseSize+length+crcSize)
	d = binary.BigEndian.AppendUint32(d, uint32(length))
	d = append(d, crced...)
	d = binary.BigEndian.AppendUint32(d, crc.Sum32())

	return e.w.Write(d)
}

// Close closes the encoder.
func (e *ChunkEncoder) Close() error {
	var i interface{} = e.w
	v, ok := i.(io.WriteCloser)
	if ok {
		return v.Close()
	}
	return nil
}
