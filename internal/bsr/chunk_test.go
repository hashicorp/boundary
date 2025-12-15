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

func TestNewBaseChunk(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	cases := []struct {
		name    string
		p       bsr.Protocol
		d       bsr.Direction
		t       *bsr.Timestamp
		typ     bsr.ChunkType
		want    *bsr.BaseChunk
		wantErr error
	}{
		{
			"valid",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			bsr.ChunkType("TEST"),
			&bsr.BaseChunk{
				Protocol:  bsr.Protocol("TEST"),
				Direction: bsr.Inbound,
				Timestamp: bsr.NewTimestamp(now),
				Type:      bsr.ChunkType("TEST"),
			},
			nil,
		},
		{
			"invalid-protocol",
			bsr.Protocol("TEST_INVALID"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			bsr.ChunkType("TEST"),
			nil,
			errors.New("bsr.NewBaseChunk: protocol name cannot be greater than 4 characters: invalid parameter"),
		},
		{
			"invalid-direction",
			bsr.Protocol("TEST"),
			bsr.UnknownDirection,
			bsr.NewTimestamp(now),
			bsr.ChunkType("TEST"),
			nil,
			errors.New("bsr.NewBaseChunk: invalid direction: invalid parameter"),
		},
		{
			"invalid-timestamp",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			nil,
			bsr.ChunkType("TEST"),
			nil,
			errors.New("bsr.NewBaseChunk: timestamp must not be nil: invalid parameter"),
		},
		{
			"invalid-chunk-type",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			bsr.ChunkType("TEST_INVALID"),
			nil,
			errors.New("bsr.NewBaseChunk: chunk type cannot be greater than 4 characters: invalid parameter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bsr.NewBaseChunk(ctx, tc.p, tc.d, tc.t, tc.typ)
			if tc.wantErr != nil {
				assert.EqualError(t, tc.wantErr, err.Error())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)

			assert.Equal(t, tc.want.Protocol, got.GetProtocol())
			assert.Equal(t, tc.want.Direction, got.GetDirection())
			assert.Equal(t, tc.want.Timestamp, got.GetTimestamp())
			assert.Equal(t, tc.want.Type, got.GetType())
			assert.Equal(t, tc.want.GetLength(), got.GetLength())
		})
	}
}
