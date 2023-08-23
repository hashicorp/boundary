// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
func (x *Timestamp) AsTime() time.Time {
	return x.GetTimestamp().AsTime()
}
