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

func TestRegisterSummaryAllocFunc_TestProtocol(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now()
	endTime := time.Now()

	cases := []struct {
		name            string
		p               bsr.Protocol
		c               bsr.ContainerType
		cf              bsr.SummaryAllocFunc
		wantP           bsr.Protocol
		want            *bsr.BaseSummary
		wantRegisterErr error
		wantGetAllocErr bool
	}{
		{
			"valid summary",
			bsr.Protocol("TEST_PROTOCOL"),
			bsr.ChannelContainer,
			func(ctx context.Context) bsr.Summary {
				return &bsr.BaseSummary{
					Id:        "TEST_ID",
					StartTime: startTime,
					EndTime:   endTime,
				}
			},
			bsr.Protocol("TEST_PROTOCOL"),
			&bsr.BaseSummary{
				Id:        "TEST_ID",
				StartTime: startTime,
				EndTime:   endTime,
			},
			nil,
			false,
		},
		{
			"already-registered-protocol",
			bsr.Protocol("TEST_PROTOCOL"),
			bsr.ChannelContainer,
			nil,
			bsr.Protocol("TEST_PROTOCOL"),
			&bsr.BaseSummary{},
			errors.New("bsr.RegisterSummaryAllocFunc: TEST_PROTOCOL channel: type already registered"),
			false,
		},
		{
			"invalid-protocol",
			bsr.Protocol("TEST_PROTOCOL_2"),
			bsr.ChannelContainer,
			nil,
			bsr.Protocol("TEST_INVALID_PROTOCOL"),
			&bsr.BaseSummary{},
			nil,
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := bsr.RegisterSummaryAllocFunc(tc.p, tc.c, tc.cf)
			if tc.wantRegisterErr != nil {
				assert.EqualError(t, tc.wantRegisterErr, err.Error())
				return
			}
			require.NoError(t, err)

			af, ok := bsr.SummaryAllocFuncs.Get(tc.wantP, tc.c)
			if tc.wantGetAllocErr {
				require.False(t, ok, "found invalid summary")
				return
			}
			require.True(t, ok, "could not get summary")

			got := af(ctx)

			assert.Equal(t, tc.want.GetId(), got.GetId())
			assert.Equal(t, tc.want.GetStartTime(), got.GetStartTime())
			assert.Equal(t, tc.want.GetEndTime(), got.GetEndTime())
		})
	}
}

func TestRegisterSummaryAllocFunc_TestChannel(t *testing.T) {
	ctx := context.Background()

	protocol := bsr.Protocol("TEST_CHANNEL_PROTOCOL")
	chs := &bsr.BaseChannelSummary{
		Id:                    "TEST_ID",
		ConnectionRecordingId: "TEST_CONNECTION_RECORDING_ID",
		ChannelType:           "CONTAINER",
		StartTime:             time.Now(),
		EndTime:               time.Now(),
		BytesUp:               100,
		BytesDown:             200,
	}

	err := bsr.RegisterSummaryAllocFunc(protocol, bsr.ChannelContainer, func(ctx context.Context) bsr.Summary {
		return chs
	})
	require.NoError(t, err)

	af, ok := bsr.SummaryAllocFuncs.Get(protocol, bsr.ChannelContainer)
	require.True(t, ok, "could not get channel summary")

	cf := af(ctx)
	got := cf.(*bsr.BaseChannelSummary)

	assert.Equal(t, chs.GetId(), got.GetId())
	assert.Equal(t, chs.GetConnectionRecordingId(), got.GetConnectionRecordingId())
	assert.Equal(t, chs.GetChannelType(), got.GetChannelType())
	assert.Equal(t, chs.GetStartTime(), got.GetStartTime())
	assert.Equal(t, chs.GetEndTime(), got.GetEndTime())
	assert.Equal(t, chs.GetBytesUp(), got.GetBytesUp())
	assert.Equal(t, chs.GetBytesDown(), got.GetBytesDown())
}

func TestRegisterSummaryAllocFunc_TestConnection(t *testing.T) {
	ctx := context.Background()

	protocol := bsr.Protocol("TEST_CONNECTION_PROTOCOL")
	chs := &bsr.BaseConnectionSummary{
		Id:           "TEST_ID",
		ChannelCount: 1,
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		BytesUp:      100,
		BytesDown:    200,
	}

	err := bsr.RegisterSummaryAllocFunc(protocol, bsr.ChannelContainer, func(ctx context.Context) bsr.Summary {
		return chs
	})
	require.NoError(t, err)

	af, ok := bsr.SummaryAllocFuncs.Get(protocol, bsr.ChannelContainer)
	require.True(t, ok, "could not get connection summary")

	cf := af(ctx)
	got := cf.(*bsr.BaseConnectionSummary)

	assert.Equal(t, chs.GetId(), got.GetId())
	assert.Equal(t, chs.GetChannelCount(), got.GetChannelCount())
	assert.Equal(t, chs.GetStartTime(), got.GetStartTime())
	assert.Equal(t, chs.GetEndTime(), got.GetEndTime())
	assert.Equal(t, chs.GetBytesUp(), got.GetBytesUp())
	assert.Equal(t, chs.GetBytesDown(), got.GetBytesDown())
}

func TestRegisterSummaryAllocFunc_TestSession(t *testing.T) {
	ctx := context.Background()

	protocol := bsr.Protocol("TEST_SESSION_PROTOCOL")
	chs := &bsr.BaseSessionSummary{
		Id:              "TEST_ID",
		ConnectionCount: 1,
		StartTime:       time.Now(),
		EndTime:         time.Now(),
	}

	err := bsr.RegisterSummaryAllocFunc(protocol, bsr.ChannelContainer, func(ctx context.Context) bsr.Summary {
		return chs
	})
	require.NoError(t, err)

	af, ok := bsr.SummaryAllocFuncs.Get(protocol, bsr.ChannelContainer)
	require.True(t, ok, "could not get session summary")

	cf := af(ctx)
	got := cf.(*bsr.BaseSessionSummary)

	assert.Equal(t, chs.GetId(), got.GetId())
	assert.Equal(t, chs.GetConnectionCount(), got.GetConnectionCount())
	assert.Equal(t, chs.GetStartTime(), got.GetStartTime())
	assert.Equal(t, chs.GetEndTime(), got.GetEndTime())
}
