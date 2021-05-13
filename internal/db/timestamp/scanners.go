package timestamp

import (
	"database/sql/driver"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// Scan implements sql.Scanner for protobuf Timestamp.
func (ts *Timestamp) Scan(value interface{}) error {
	switch t := value.(type) {
	case time.Time:
		ts.Timestamp = timestamppb.New(t) // google proto version
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
