package store

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
)

// Scan supports Timestamps for oplogs
func (ts *Timestamp) Scan(value interface{}) error {
	if ts == nil {
		return errors.New("Timestamp is nil")
	}
	switch t := value.(type) {
	case time.Time:
		var err error
		ts.Timestamp, err = ptypes.TimestampProto(t) // google proto version
		if err != nil {
			return fmt.Errorf("error converting the timestamp: %w", err)
		}
	default:
		return errors.New("Not a protobuf Timestamp")
	}
	return nil
}

// Value supports Timestamps for oplogs
func (ts *Timestamp) Value() (driver.Value, error) {
	if ts == nil {
		return nil, nil
	}
	return ptypes.Timestamp(ts.Timestamp)
}
