// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package bsr

import "time"

type (
	// SessionSummary encapsulates data for a session, including its session id, connection count,
	// and start/end time using a monotonic clock
	SessionSummary struct {
		Id              string
		ConnectionCount uint64
		StartTime       time.Time
		EndTime         time.Time
		Errors          error
	}

	// ConnectionSummary encapsulates data for a connection, including its connection id, channel count,
	// start/end time using a monotonic clock, and the aggregate bytes up/ down of its channels
	ConnectionSummary struct {
		Id           string
		ChannelCount uint64
		StartTime    time.Time
		EndTime      time.Time
		BytesUp      uint64
		BytesDown    uint64
		Errors       error
	}

	// ChannelSummary encapsulates data for a channel, including its id, channel type,
	// start/end time using a monotonic clock, and the bytes up/ down seen on this channel
	ChannelSummary struct {
		Id                    string
		ConnectionRecordingId string
		StartTime             time.Time
		EndTime               time.Time
		BytesUp               uint64
		BytesDown             uint64
		ChannelType           string
	}
)
