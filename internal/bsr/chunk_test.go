// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr"
	"github.com/hashicorp/boundary/internal/errors"
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
			errors.New(ctx, errors.InvalidParameter, "bsr.NewBaseChunk", "protocol name cannot be greater than 4 characters"),
		},
		{
			"invalid-direction",
			bsr.Protocol("TEST"),
			bsr.UnknownDirection,
			bsr.NewTimestamp(now),
			bsr.ChunkType("TEST"),
			nil,
			errors.New(ctx, errors.InvalidParameter, "bsr.NewBaseChunk", "invalid direction"),
		},
		{
			"invalid-timestamp",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			nil,
			bsr.ChunkType("TEST"),
			nil,
			errors.New(ctx, errors.InvalidParameter, "bsr.NewBaseChunk", "timestamp must not be nil"),
		},
		{
			"invalid-chunk-type",
			bsr.Protocol("TEST"),
			bsr.Inbound,
			bsr.NewTimestamp(now),
			bsr.ChunkType("TEST_INVALID"),
			nil,
			errors.New(ctx, errors.InvalidParameter, "bsr.NewBaseChunk", "chunk type cannot be greater than 4 characters"),
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
