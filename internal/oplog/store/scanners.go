package store

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"github.com/gogo/protobuf/types"
	// "github.com/golang/protobuf/ptypes"
)

// Scan supports Timestamps for oplogs
func (ts *Timestamp) Scan(value interface{}) error {
	switch t := value.(type) {
	case time.Time:
		var err error
		ts.Timestamp, err = types.TimestampProto(t) // gogo version
		// ts.Timestamp, err = ptypes.TimestampProto(t) // google proto version
		if err != nil {
			return fmt.Errorf("error converting the timestamp: %w", err)
		}
	default:
		return errors.New("Not a protobuf Timestamp")
	}
	return nil
}

// Value supports Timestamps for oplogs
func (ts Timestamp) Value() (driver.Value, error) {
	return types.TimestampFromProto(ts.Timestamp) // gogo version
	// return ptypes.Timestamp(ts.Timestamp)
}
