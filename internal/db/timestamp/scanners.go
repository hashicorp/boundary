package timestamp

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
)

// Scan implements sql.Scanner for protobuf Timestamp.
func (ts *Timestamp) Scan(value interface{}) error {
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

// Scan implements driver.Valuer for protobuf Timestamp.
func (ts *Timestamp) Value() (driver.Value, error) {
	if ts == nil {
		return nil, nil
	}
	return ptypes.Timestamp(ts.Timestamp)
}
