// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/boundary/internal/bsr"
)

func init() {
	if err := bsr.RegisterChunkType("TEST", "TEST", func(_ context.Context, bc *bsr.BaseChunk, data []byte) (bsr.Chunk, error) {
		return &testChunk{
			BaseChunk: bc,
			Data:      data,
		}, nil
	}); err != nil {
		panic(err)
	}
	if err := bsr.RegisterChunkType("TEST", "ERRR", func(_ context.Context, bc *bsr.BaseChunk, data []byte) (bsr.Chunk, error) {
		return nil, errors.New("error in decode function")
	}); err != nil {
		panic(err)
	}
}

func TestChunkDecoder(t *testing.T) {
	ctx := context.Background()

	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)

	cases := []struct {
		name    string
		encoded []byte
		want    []bsr.Chunk
	}{
		{
			"header-no-compression",
			[]byte(
				"" + // so everything else aligns better
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x00" + // compression method
					"\x00" + // encryption method
					"sess_123456789" + // data
					"\xbe\x4c\x7c\x20" + // crc
					"",
			),
			[]bsr.Chunk{
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  "TEST",
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
			},
		},
		{
			"header-end-no-compression",
			[]byte(
				"" + // header
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x00" + // compression method
					"\x00" + // encryption method
					"sess_123456789" + // data
					"\xbe\x4c\x7c\x20" + // crc
					"" + // end
					"\x00\x00\x00\x00" + // length
					"TEST" + // protocol
					"DONE" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x13" + // time nanoseconds
					"\x50\x91\xfe\x72" + // crc
					"",
			),
			[]bsr.Chunk{
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  "TEST",
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  "TEST",
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Nanosecond * 5)),
						Type:      bsr.ChunkEnd,
					},
				},
			},
		},
		{
			"header-test-end-no-compression",
			[]byte(
				"" + // header
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x00" + // compression method
					"\x00" + // encryption method
					"sess_123456789" + // data
					"\xbe\x4c\x7c\x20" + // crc
					"" + // test
					"\x00\x00\x00\x03" + // length
					"TEST" + // protocol
					"TEST" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"foo" + // data
					"\xa4\x6e\x48\x70" + // crc
					"" + // end
					"\x00\x00\x00\x00" + // length
					"TEST" + // protocol
					"DONE" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x13" + // time nanoseconds
					"\x50\x91\xfe\x72" + // crc
					"",
			),
			[]bsr.Chunk{
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  "TEST",
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.NoCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&testChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  "TEST",
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      "TEST",
					},
					Data: []byte("foo"),
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  "TEST",
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Nanosecond * 5)),
						Type:      bsr.ChunkEnd,
					},
				},
			},
		},
		{
			"header-test-end-gzip-compression",
			[]byte(
				"" + // header
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x01" + // compression method
					"\x00" + // encryption method
					"sess_123456789" + // data
					"\x10\x24\xed\xb1" + // crc
					"" + // test
					"\x00\x00\x00\x1b" + // length
					"TEST" + // protocol
					"TEST" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					gziped("foo") + // data
					"\x29\x8e\x22\x12" + // crc
					"" + // end
					"\x00\x00\x00\x00" + // length
					"TEST" + // protocol
					"DONE" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x13" + // time nanoseconds
					"\x50\x91\xfe\x72" + // crc
					"",
			),
			[]bsr.Chunk{
				&bsr.HeaderChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  "TEST",
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      bsr.ChunkHeader,
					},
					Compression: bsr.GzipCompression,
					Encryption:  bsr.NoEncryption,
					SessionId:   "sess_123456789",
				},
				&testChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  "TEST",
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts),
						Type:      "TEST",
					},
					Data: []byte("foo"),
				},
				&bsr.EndChunk{
					BaseChunk: &bsr.BaseChunk{
						Protocol:  "TEST",
						Direction: bsr.Inbound,
						Timestamp: bsr.NewTimestamp(ts.Add(time.Nanosecond * 5)),
						Type:      bsr.ChunkEnd,
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer(tc.encoded)
			dec, err := bsr.NewChunkDecoder(ctx, buf)
			require.NoError(t, err)

			got := make([]bsr.Chunk, 0, len(tc.want))
			for {
				c, err := dec.Decode(ctx)
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				got = append(got, c)
			}

			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNewChunkDecoderErrors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		r    io.Reader
		want error
	}{
		{
			"nil-reader",
			nil,
			errors.New("bsr.NewChunkDecoder: reader cannot be nil: invalid parameter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bsr.NewChunkDecoder(ctx, tc.r)
			assert.EqualError(t, err, tc.want.Error())
		})
	}
}

func TestChunkDecoderDecodeErrors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		r    io.Reader
		want error
	}{
		{
			"unknown-chunk-type",
			bytes.NewBuffer([]byte(
				"" + // test
					"\x00\x00\x00\x03" + // length
					"TEST" + // protocol
					"UNKW" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"foo" + // data
					"\x01\x96\x41\x8a" + // crc
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: unsupported chunk type UNKW for protocol TEST: error decoding chunk"),
		},
		{
			"unknown-chunk-type-for-protocol",
			bytes.NewBuffer([]byte(
				"" + // test
					"\x00\x00\x00\x03" + // length
					"UNKW" + // protocol
					"TEST" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"foo" + // data
					"\x38\xbd\xb9\xee" + // crc
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: unsupported chunk type TEST for protocol UNKW: error decoding chunk"),
		},
		{
			"chuck-missing-base-fields",
			bytes.NewBuffer([]byte(
				"" + // so everything else aligns better
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: unexpected EOF: error decoding chunk"),
		},
		{
			"chuck-length-exceeds-max",
			bytes.NewBuffer([]byte(
				"" + // so everything else aligns better
					"\xff\xff\xff\xff" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x00" + // compression method
					"\x00" + // encryption method
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: chunk length 4294967295 exceeds max chunk length of 6400000: error decoding chunk"),
		},
		{
			"chuck-missing-data",
			bytes.NewBuffer([]byte(
				"" + // so everything else aligns better
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: unexpected EOF: missing data: error decoding chunk"),
		},
		{
			"chuck-partial-missing-data",
			bytes.NewBuffer([]byte(
				"" + // so everything else aligns better
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x00" + // compression method
					"\x00" + // encryption method
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: unexpected EOF: missing data: error decoding chunk"),
		},
		{
			"chuck-missing-crc",
			bytes.NewBuffer([]byte(
				"" + // so everything else aligns better
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x00" + // compression method
					"\x00" + // encryption method
					"sess_123456789" + // data
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: unexpected EOF: missing crc: error decoding chunk"),
		},
		{
			"chuck-partial-missing-crc",
			bytes.NewBuffer([]byte(
				"" + // so everything else aligns better
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x00" + // compression method
					"\x00" + // encryption method
					"sess_123456789" + // data
					"\xbe\x4c\x7c" + // crc
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: unexpected EOF: missing crc: error decoding chunk"),
		},
		{
			"chuck-crc-mismatch",
			bytes.NewBuffer([]byte(
				"" + // so everything else aligns better
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x00" + // compression method
					"\x00" + // encryption method
					"sess_123456789" + // data
					"\xbe\x4c\x7c\x00" + // crc
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: chunk crc did not match: error decoding chunk"),
		},
		{
			"chuck-invalid-direction",
			bytes.NewBuffer([]byte(
				"" + // so everything else aligns better
					"\x00\x00\x00\x10" + // length
					"TEST" + // protocol
					"HEAD" + // type
					"\x00" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"\x00" + // compression method
					"\x00" + // encryption method
					"sess_123456789" + // data
					"\xdd\x4b\xa5\x04" + // crc
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: bsr.NewBaseChunk: invalid direction: invalid parameter: error decoding chunk"),
		},
		{
			"chuck-decode-function-error",
			bytes.NewBuffer([]byte(
				"" + // so everything else aligns better
					"\x00\x00\x00\x03" + // length
					"TEST" + // protocol
					"ERRR" + // type
					"\x01" + // direction
					"\x00\x00\x00\x00\x64\x12\xf3\xa7" + // time seconds
					"\x00\x00\x00\x0e" + // time nanoseconds
					"foo" + // data
					"\x30\xd5\x69\xbb" + // crc
					"",
			)),
			errors.New("bsr.(ChunkDecoder).Decode: error in decode function: error decoding chunk"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := bsr.NewChunkDecoder(ctx, tc.r)
			require.NoError(t, err)

			_, err = dec.Decode(ctx)
			assert.EqualError(t, err, tc.want.Error())
		})
	}
}
