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
