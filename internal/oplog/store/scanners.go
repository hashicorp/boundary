package store

import (
	"database/sql/driver"
	fmt "fmt"
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
		// ts.Timestamp, err = ptypes.TimestampProto(t)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Not a protobuf Timestamp")
	}
	return nil
}

// Value supports Timestamps for oplogs
func (ts Timestamp) Value() (driver.Value, error) {
	return types.TimestampFromProto(ts.Timestamp) // gogo version
	// return ptypes.Timestamp(ts.Timestamp)
}
