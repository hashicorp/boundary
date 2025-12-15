// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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

func TestNewEndChunk(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	cases := []struct {
		name    string
		p       bsr.Protocol
		d       bsr.Direction
		t       *bsr.Timestamp
		want    *bsr.EndChunk
		wantErr error
	}{
		{
			"valid-nocompression-noencrpytion",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			&bsr.EndChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  bsr.Protocol("TEST"),
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(now),
					Type:      bsr.ChunkEnd,
				},
			},
			nil,
		},
		{
			"valid-gzip-noencrpytion",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			&bsr.EndChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  bsr.Protocol("TEST"),
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(now),
					Type:      bsr.ChunkEnd,
				},
			},
			nil,
		},
		{
			"invalid-protocol",
			bsr.Protocol("TEST_INVALID"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			nil,
			errors.New("bsr.NewBaseChunk: protocol name cannot be greater than 4 characters: invalid parameter"),
		},
		{
			"invalid-direction",
			bsr.Protocol("TEST"),
			bsr.UnknownDirection,
			bsr.NewTimestamp(now),
			nil,
			errors.New("bsr.NewBaseChunk: invalid direction: invalid parameter"),
		},
		{
			"invalid-timestamp",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			nil,
			nil,
			errors.New("bsr.NewBaseChunk: timestamp must not be nil: invalid parameter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bsr.NewEnd(ctx, tc.p, tc.d, tc.t)
			if tc.wantErr != nil {
				assert.EqualError(t, tc.wantErr, err.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEndMarshalData(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	cases := []struct {
		name string
		h    *bsr.EndChunk
		want []byte
	}{
		{
			"nocompression-noencrpytion",
			&bsr.EndChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  bsr.Protocol("TEST"),
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(now),
					Type:      bsr.ChunkEnd,
				},
			},
			nil,
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

func TestDecodeEnd(t *testing.T) {
	ctx := context.Background()

	ts := time.Date(2023, time.March, 16, 10, 47, 3, 14, time.UTC)

	cases := []struct {
		name    string
		bc      *bsr.BaseChunk
		encoded []byte
		want    bsr.Chunk
		wantErr error
	}{
		{
			"header-no-compression",
			&bsr.BaseChunk{
				Protocol:  "TEST",
				Direction: bsr.Inbound,
				Timestamp: bsr.NewTimestamp(ts),
				Type:      bsr.ChunkEnd,
			},
			[]byte(""),
			&bsr.EndChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol:  "TEST",
					Direction: bsr.Inbound,
					Timestamp: bsr.NewTimestamp(ts),
					Type:      bsr.ChunkEnd,
				},
			},
			nil,
		},
		{
			"header-wrong-type",
			&bsr.BaseChunk{
				Protocol:  "TEST",
				Direction: bsr.Inbound,
				Timestamp: bsr.NewTimestamp(ts),
				Type:      "TEST",
			},
			[]byte(""),
			nil,
			errors.New("bsr.DecodeEnd: invalid chunk type TEST"),
		},
		{
			"header-nil-base-chunk",
			nil,
			[]byte(""),
			nil,
			errors.New("bsr.DecodeEnd: nil base chunk: invalid parameter"),
		},
		{
			"header-extra-data",
			&bsr.BaseChunk{
				Protocol:  "TEST",
				Direction: bsr.Inbound,
				Timestamp: bsr.NewTimestamp(ts),
				Type:      bsr.ChunkEnd,
			},
			[]byte("foo"),
			nil,
			errors.New("bsr.DecodeEnd: end chunk not empty"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bsr.DecodeEnd(ctx, tc.bc, tc.encoded)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
