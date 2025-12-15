// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewChunkScanner(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		reader  io.Reader
		opts    []bsr.Option
		wantErr error
	}{
		{
			"valid",
			bytes.NewBuffer([]byte(
				string(bsr.Magic) +
					"",
			)),
			nil,
			nil,
		},
		{
			"valid-with-sha256sum",
			bytes.NewBuffer([]byte(
				string(bsr.Magic) +
					"",
			)),
			[]bsr.Option{bsr.WithSha256Sum([]byte("797cf38f8e3efa3da3ae95449466ffd62cfe084abd1c1134f9e74474e79570f0"))},
			nil,
		},
		{
			"nil-reader",
			nil,
			[]bsr.Option{bsr.WithSha256Sum([]byte("797cf38f8e3efa3da3ae95449466ffd62cfe084abd1c1134f9e74474e79570f0"))},
			fmt.Errorf("bsr.NewChunkScanner: reader is nil: invalid parameter"),
		},
		{
			"no-magic",
			bytes.NewBuffer([]byte("NOT_BSR_MAGIC")),
			nil,
			fmt.Errorf("bsr.NewChunkScanner: bsr.ReadMagic: invalid magic string"),
		},
		{
			"not-enough-data",
			bytes.NewBuffer(bsr.Magic.Bytes()[:2]),
			nil,
			fmt.Errorf("bsr.NewChunkScanner: bsr.ReadMagic: crypto.(Sha256SumReader).Read: EOF"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bsr.NewChunkScanner(ctx, tc.reader, tc.opts...)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestChunkScanner(t *testing.T) {
	ctx := context.Background()

	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)

	cases := []struct {
		name    string
		reader  io.Reader
		opts    []bsr.Option
		want    bsr.Chunk
		wantErr error
	}{
		{
			"header",
			bytes.NewBuffer([]byte(
				string(bsr.Magic) +
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
			)),
			nil,
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
			nil,
		},
		{
			"checksum-eof",
			bytes.NewBuffer([]byte(
				string(bsr.Magic) +
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
			)),
			[]bsr.Option{bsr.WithSha256Sum([]byte("foo"))},
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
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := bsr.NewChunkScanner(ctx, tc.reader, tc.opts...)
			require.NoError(t, err)

			got, err := scanner.Scan(ctx)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.Equal(t, tc.want, got)
		})
	}
}

func TestChunkWalk(t *testing.T) {
	ctx := context.Background()

	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)

	headerTest := []byte(
		string(bsr.Magic) +
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
			"",
	)
	headerTestEnd := append(headerTest, []byte(
		""+ // end
			"\x00\x00\x00\x00"+ // length
			"TEST"+ // protocol
			"DONE"+ // type
			"\x01"+ // direction
			"\x00\x00\x00\x00\x64\x12\xf3\xa7"+ // time seconds
			"\x00\x00\x00\x13"+ // time nanoseconds
			"\x50\x91\xfe\x72"+ // crc
			"",
	)...)

	cases := []struct {
		name    string
		reader  io.Reader
		opts    []bsr.Option
		f       func(t *testing.T, got *[]bsr.Chunk) bsr.ChunkReadFunc
		want    []bsr.Chunk
		wantErr error
	}{
		{
			"no-chunk",
			bytes.NewBuffer([]byte(
				string(bsr.Magic) +
					"",
			)),
			nil,
			func(t *testing.T, _ *[]bsr.Chunk) bsr.ChunkReadFunc {
				return func(_ context.Context, c bsr.Chunk) error {
					assert.Fail(t, "read func should not be called")
					return nil
				}
			},
			[]bsr.Chunk{},
			nil,
		},
		{
			"header-test-end",
			bytes.NewBuffer(headerTestEnd),
			nil,
			func(t *testing.T, got *[]bsr.Chunk) bsr.ChunkReadFunc {
				return func(_ context.Context, c bsr.Chunk) error {
					*got = append(*got, c)
					return nil
				}
			},
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
			nil,
		},
		{
			"header-test-end-checksumed",
			bytes.NewBuffer(headerTestEnd),
			[]bsr.Option{bsr.WithSha256Sum(func() []byte {
				b, err := crypto.Sha256Sum(ctx, bytes.NewBuffer(headerTestEnd), crypto.WithHexEncoding(true))
				require.NoError(t, err)
				return b
			}())},
			func(t *testing.T, got *[]bsr.Chunk) bsr.ChunkReadFunc {
				return func(_ context.Context, c bsr.Chunk) error {
					*got = append(*got, c)
					return nil
				}
			},
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
			nil,
		},
		{
			"header-test-no-end",
			bytes.NewBuffer(headerTest),
			nil,
			func(t *testing.T, got *[]bsr.Chunk) bsr.ChunkReadFunc {
				return func(_ context.Context, c bsr.Chunk) error {
					*got = append(*got, c)
					return nil
				}
			},
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
			},
			nil,
		},
		{
			"header-test-no-end-checksumed",
			bytes.NewBuffer(headerTest),
			[]bsr.Option{bsr.WithSha256Sum(func() []byte {
				b, err := crypto.Sha256Sum(ctx, bytes.NewBuffer(headerTest), crypto.WithHexEncoding(true))
				require.NoError(t, err)
				return b
			}())},
			func(t *testing.T, got *[]bsr.Chunk) bsr.ChunkReadFunc {
				return func(_ context.Context, c bsr.Chunk) error {
					*got = append(*got, c)
					return nil
				}
			},
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
			},
			nil,
		},
		{
			"func-errors",
			bytes.NewBuffer([]byte(
				string(bsr.Magic) +
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
			)),
			nil,
			func(t *testing.T, got *[]bsr.Chunk) bsr.ChunkReadFunc {
				return func(_ context.Context, c bsr.Chunk) error {
					return fmt.Errorf("error in walk function")
				}
			},
			nil,
			fmt.Errorf("bsr.ChunkWalk: error in walk function"),
		},
		{
			"incorrect-checksum",
			bytes.NewBuffer(headerTestEnd),
			[]bsr.Option{bsr.WithSha256Sum([]byte("f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"))},
			func(t *testing.T, got *[]bsr.Chunk) bsr.ChunkReadFunc {
				return func(_ context.Context, c bsr.Chunk) error {
					*got = append(*got, c)
					return nil
				}
			},
			nil,
			fmt.Errorf("bsr.ChunkWalk: bsr.(ChunkScanner).Scan: computed checksum did NOT match"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := bsr.NewChunkScanner(ctx, tc.reader, tc.opts...)
			require.NoError(t, err)
			got := make([]bsr.Chunk, 0, len(tc.want))
			err = bsr.ChunkWalk(ctx, scanner, tc.f(t, &got))
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
