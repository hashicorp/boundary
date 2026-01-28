// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testChunk struct {
	*bsr.BaseChunk
	Data []byte
	err  error
}

// MarshalData serializes the data portion of a chunk.
func (t *testChunk) MarshalData(_ context.Context) ([]byte, error) {
	if t.err != nil {
		return nil, t.err
	}
	return t.Data, nil
}

func gziped(d string) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte(d))
	w.Close()
	return buf.String()
}

func TestChunkEncoder(t *testing.T) {
	ctx := context.Background()

	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)

	cases := []struct {
		name   string
		c      bsr.Compression
		e      bsr.Encryption
		chunks []bsr.Chunk
		want   []byte
	}{
		{
			"header-no-compression",
			bsr.NoCompression,
			bsr.NoEncryption,
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
		},
		{
			"header-end-no-compression",
			bsr.NoCompression,
			bsr.NoEncryption,
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
		},
		{
			"header-test-end-no-compression",
			bsr.NoCompression,
			bsr.NoEncryption,
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
		},
		{
			"header-test-end-gzip-compression",
			bsr.GzipCompression,
			bsr.NoEncryption,
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
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := fstest.NewTempBuffer()
			require.NoError(t, err)
			enc, err := bsr.NewChunkEncoder(ctx, buf, tc.c, tc.e)
			require.NoError(t, err)

			var wrote int
			for _, c := range tc.chunks {
				w, err := enc.Encode(ctx, c)
				require.NoError(t, err)
				wrote += w
			}

			got := buf.Bytes()
			assert.Equal(t, len(tc.want), wrote)
			assert.Equal(t, tc.want, got)
		})
	}
}

type errorWriter struct{}

func (e errorWriter) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

func (e errorWriter) WriteAndClose(_ []byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

func TestChunkEncoderEncodeError(t *testing.T) {
	ctx := context.Background()

	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)

	cases := []struct {
		name  string
		w     storage.Writer
		c     bsr.Compression
		e     bsr.Encryption
		chunk bsr.Chunk
		want  error
	}{
		{
			"chunk-marshal-error",
			func() storage.Writer {
				buf, err := fstest.NewTempBuffer()
				require.NoError(t, err)
				return buf
			}(),
			bsr.NoCompression,
			bsr.NoEncryption,
			&testChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  "TEST",
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(ts),
					Type:      "TEST",
				},
				err: fmt.Errorf("marshal error"),
			},
			fmt.Errorf("marshal error"),
		},
		{
			"writer-error",
			func() storage.Writer { return errorWriter{} }(),
			bsr.NoCompression,
			bsr.NoEncryption,
			&testChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  "TEST",
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(ts),
					Type:      "TEST",
				},
				Data: []byte("foo"),
			},
			fmt.Errorf("write error"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := bsr.NewChunkEncoder(ctx, tc.w, tc.c, tc.e)
			require.NoError(t, err)

			_, err = enc.Encode(ctx, tc.chunk)
			assert.EqualError(t, tc.want, err.Error())
		})
	}
}

func TestChunkEncoderErrors(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		w    storage.Writer
		c    bsr.Compression
		e    bsr.Encryption
		want error
	}{
		{
			"invalid-compression",
			func() storage.Writer {
				buf, err := fstest.NewTempBuffer()
				require.NoError(t, err)
				return buf
			}(),
			bsr.Compression(255),
			bsr.NoEncryption,
			errors.New("bsr.NewChunkEncoder: invalid compression: invalid parameter"),
		},
		{
			"invalid-encryption",
			func() storage.Writer {
				buf, err := fstest.NewTempBuffer()
				require.NoError(t, err)
				return buf
			}(),
			bsr.NoCompression,
			bsr.Encryption(255),
			errors.New("bsr.NewChunkEncoder: invalid encryption: invalid parameter"),
		},
		{
			"nil-writer",
			nil,
			bsr.NoCompression,
			bsr.NoEncryption,
			errors.New("bsr.NewChunkEncoder: writer cannot be nil: invalid parameter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bsr.NewChunkEncoder(ctx, tc.w, tc.c, tc.e)
			require.EqualError(t, tc.want, err.Error())
		})
	}
}
