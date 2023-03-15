// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHeaderChunk(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	cases := []struct {
		name      string
		p         bsr.Protocol
		d         bsr.Direction
		t         *bsr.Timestamp
		c         bsr.Compression
		e         bsr.Encryption
		sessionId string
		want      *bsr.HeaderChunk
		wantErr   error
	}{
		{
			"valid-nocompression-noencrpytion",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			bsr.NoCompression,
			bsr.NoEncryption,
			"sess_123456789",
			&bsr.HeaderChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  bsr.Protocol("TEST"),
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(now),
					Type:      bsr.ChunkHeader,
				},
				Compression: bsr.NoCompression,
				Encryption:  bsr.NoEncryption,
				SessionId:   "sess_123456789",
			},
			nil,
		},
		{
			"valid-gzip-noencrpytion",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			bsr.GzipCompression,
			bsr.NoEncryption,
			"sess_123456789",
			&bsr.HeaderChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  bsr.Protocol("TEST"),
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(now),
					Type:      bsr.ChunkHeader,
				},
				Compression: bsr.GzipCompression,
				Encryption:  bsr.NoEncryption,
				SessionId:   "sess_123456789",
			},
			nil,
		},
		{
			"invalid-protocol",
			bsr.Protocol("TEST_INVALID"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			bsr.NoCompression,
			bsr.NoEncryption,
			"sess_123456789",
			nil,
			errors.New("bsr.NewBaseChunk: protocol name cannot be greater than 4 characters: invalid parameter"),
		},
		{
			"invalid-direction",
			bsr.Protocol("TEST"),
			bsr.UnknownDirection,
			bsr.NewTimestamp(now),
			bsr.NoCompression,
			bsr.NoEncryption,
			"sess_123456789",
			nil,
			errors.New("bsr.NewBaseChunk: invalid direction: invalid parameter"),
		},
		{
			"invalid-timestamp",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			nil,
			bsr.NoCompression,
			bsr.NoEncryption,
			"sess_123456789",
			nil,
			errors.New("bsr.NewBaseChunk: timestamp must not be nil: invalid parameter"),
		},
		{
			"invalid-compression",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			bsr.Compression(255),
			bsr.NoEncryption,
			"sess_123456789",
			nil,
			errors.New("bsr.NewHeader: invalid compression: invalid parameter"),
		},
		{
			"invalid-encryption",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			bsr.NoCompression,
			bsr.Encryption(255),
			"sess_123456789",
			nil,
			errors.New("bsr.NewHeader: invalid encryption: invalid parameter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bsr.NewHeader(ctx, tc.p, tc.d, tc.t, tc.c, tc.e, tc.sessionId)
			if tc.wantErr != nil {
				assert.EqualError(t, tc.wantErr, err.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHeaderMarshalData(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	cases := []struct {
		name string
		h    *bsr.HeaderChunk
		want []byte
	}{
		{
			"nocompression-noencrpytion",
			&bsr.HeaderChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  bsr.Protocol("TEST"),
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(now),
					Type:      bsr.ChunkHeader,
				},
				Compression: bsr.NoCompression,
				Encryption:  bsr.NoEncryption,
				SessionId:   "sess_123456789",
			},
			[]byte("\x00\x00sess_123456789"),
		},
		{
			"gzip-noencrpytion",
			&bsr.HeaderChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  bsr.Protocol("TEST"),
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(now),
					Type:      bsr.ChunkHeader,
				},
				Compression: bsr.GzipCompression,
				Encryption:  bsr.NoEncryption,
				SessionId:   "sess_123456789",
			},
			[]byte("\x01\x00sess_123456789"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.h.MarshalData(ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
