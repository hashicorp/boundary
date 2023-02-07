// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package timestamp

import (
	"database/sql/driver"
	"errors"
	"math"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	NegativeInfinityTS = time.Date(math.MinInt32, time.January, 1, 0, 0, 0, 0, time.UTC)
	PositiveInfinityTS = time.Date(math.MaxInt32, time.December, 31, 23, 59, 59, 1e9-1, time.UTC)
)

// Scan implements sql.Scanner for protobuf Timestamp.
func (ts *Timestamp) Scan(value any) error {
	switch t := value.(type) {
	case time.Time:
		ts.Timestamp = timestamppb.New(t) // google proto version
	case string:
		switch value {
		case "-infinity":
			ts.Timestamp = timestamppb.New(NegativeInfinityTS)
		case "infinity":
			ts.Timestamp = timestamppb.New(PositiveInfinityTS)
		}
	default:
		return errors.New("Not a protobuf Timestamp")
	}
	return nil
}

// Scan implements driver.Valuer for protobuf Timestamp.
func (ts *Timestamp) Value() (driver.Value, error) {
	if ts == nil {
		return nil, nil
	}
	return ts.Timestamp.AsTime(), nil
}

// GormDataType gorm common data type (required)
func (ts *Timestamp) GormDataType() string {
	return "timestamp"
}
