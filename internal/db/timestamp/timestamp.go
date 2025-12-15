// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package timestamp

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// New constructs a new Timestamp from the provided time.Time.
func New(t time.Time) *Timestamp {
	return &Timestamp{
		Timestamp: timestamppb.New(t),
	}
}

// Now constructs a new Timestamp from the current time.
func Now() *Timestamp {
	return &Timestamp{
		Timestamp: timestamppb.Now(),
	}
}

// AsTime converts x to a time.Time.
func (ts *Timestamp) AsTime() time.Time {
	return ts.GetTimestamp().AsTime()
}
