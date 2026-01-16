// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterSummaryAllocFunc_TestProtocol(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now()
	endTime := time.Now()

	cases := []struct {
		name            string
		p               Protocol
		c               ContainerType
		cf              SummaryAllocFunc
		wantP           Protocol
		want            *BaseSummary
		wantRegisterErr error
		wantGetAllocErr bool
	}{
		{
			"valid summary",
			Protocol("TEST_PROTOCOL"),
			ChannelContainer,
			func(ctx context.Context) Summary {
				return &BaseSummary{
					Id:        "TEST_ID",
					StartTime: startTime,
					EndTime:   endTime,
				}
			},
			Protocol("TEST_PROTOCOL"),
			&BaseSummary{
				Id:        "TEST_ID",
				StartTime: startTime,
				EndTime:   endTime,
			},
			nil,
			false,
		},
		{
			"already-registered-container",
			Protocol("TEST_PROTOCOL"),
			ChannelContainer,
			nil,
			Protocol("TEST_PROTOCOL"),
			&BaseSummary{},
			errors.New("bsr.RegisterSummaryAllocFunc: TEST_PROTOCOL protocol with channel container: type already registered"),
			false,
		},
		{
			"invalid-protocol",
			Protocol("TEST_PROTOCOL_2"),
			ChannelContainer,
			nil,
			Protocol("TEST_INVALID_PROTOCOL"),
			&BaseSummary{},
			nil,
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RegisterSummaryAllocFunc(tc.p, tc.c, tc.cf)
			if tc.wantRegisterErr != nil {
				assert.EqualError(t, tc.wantRegisterErr, err.Error())
				return
			}
			require.NoError(t, err)

			af, ok := summaryAllocFuncs.get(tc.wantP, tc.c)
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

	protocol := Protocol("TEST_CHANNEL_PROTOCOL")
	chs := &BaseChannelSummary{
		Id:                    "TEST_ID",
		ConnectionRecordingId: "TEST_CONNECTION_RECORDING_ID",
		ChannelType:           "CONTAINER",
		StartTime:             time.Now(),
		EndTime:               time.Now(),
		BytesUp:               100,
		BytesDown:             200,
	}

	err := RegisterSummaryAllocFunc(protocol, ChannelContainer, func(ctx context.Context) Summary {
		return chs
	})
	require.NoError(t, err)

	af, ok := summaryAllocFuncs.get(protocol, ChannelContainer)
	require.True(t, ok, "could not get channel summary")

	cf := af(ctx)
	got := cf.(*BaseChannelSummary)

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

	protocol := Protocol("TEST_CONNECTION_PROTOCOL")
	chs := &BaseConnectionSummary{
		Id:           "TEST_ID",
		ChannelCount: 1,
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		BytesUp:      100,
		BytesDown:    200,
	}

	err := RegisterSummaryAllocFunc(protocol, ConnectionContainer, func(ctx context.Context) Summary {
		return chs
	})
	require.NoError(t, err)

	af, ok := summaryAllocFuncs.get(protocol, ConnectionContainer)
	require.True(t, ok, "could not get connection summary")

	cf := af(ctx)
	got := cf.(*BaseConnectionSummary)

	assert.Equal(t, chs.GetId(), got.GetId())
	assert.Equal(t, chs.GetChannelCount(), got.GetChannelCount())
	assert.Equal(t, chs.GetStartTime(), got.GetStartTime())
	assert.Equal(t, chs.GetEndTime(), got.GetEndTime())
	assert.Equal(t, chs.GetBytesUp(), got.GetBytesUp())
	assert.Equal(t, chs.GetBytesDown(), got.GetBytesDown())
}

func TestRegisterSummaryAllocFunc_TestSession(t *testing.T) {
	ctx := context.Background()

	protocol := Protocol("TEST_SESSION_PROTOCOL")
	chs := &BaseSessionSummary{
		Id:              "TEST_ID",
		ConnectionCount: 1,
		StartTime:       time.Now(),
		EndTime:         time.Now(),
	}

	err := RegisterSummaryAllocFunc(protocol, SessionContainer, func(ctx context.Context) Summary {
		return chs
	})
	require.NoError(t, err)

	af, ok := summaryAllocFuncs.get(protocol, SessionContainer)
	require.True(t, ok, "could not get session summary")

	cf := af(ctx)
	got := cf.(*BaseSessionSummary)

	assert.Equal(t, chs.GetId(), got.GetId())
	assert.Equal(t, chs.GetConnectionCount(), got.GetConnectionCount())
	assert.Equal(t, chs.GetStartTime(), got.GetStartTime())
	assert.Equal(t, chs.GetEndTime(), got.GetEndTime())
}
