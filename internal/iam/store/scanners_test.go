package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
)

func Test_TimestampValue(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		ts := Timestamp{Timestamp: &timestamp.Timestamp{Seconds: 0, Nanos: 0}}
		v, err := ts.Value()
		assert.NoError(err)
		assert.Equal(v, utcDate(1970, 1, 1))
	})
	t.Run("valid nil ts", func(t *testing.T) {
		var ts *Timestamp
		v, err := ts.Value()
		assert.NoError(err)
		assert.Equal(v, nil)
	})
	t.Run("invalid ts", func(t *testing.T) {
		ts := Timestamp{Timestamp: &timestamp.Timestamp{Seconds: maxValidSeconds, Nanos: 0}}
		v, err := ts.Value()
		assert.NotNil(err)
		assert.Equal(err.Error(), "timestamp: seconds:253402300800 after 10000-01-01")
		assert.Equal(v, utcDate(10000, 1, 1))
	})
}

func Test_TimestampScan(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		v := time.Unix(0, 0)
		ts := Timestamp{}
		err := ts.Scan(v)
		assert.NoError(err)
		assert.True(reflect.DeepEqual(ts.Timestamp, &timestamp.Timestamp{Seconds: 0, Nanos: 0}))
	})
	t.Run("valid default time", func(t *testing.T) {
		var v time.Time
		ts := Timestamp{}
		err := ts.Scan(v)
		assert.NoError(err)
		assert.True(reflect.DeepEqual(ts.Timestamp, &timestamp.Timestamp{Seconds: -62135596800, Nanos: 0}))
	})
	t.Run("invalid type", func(t *testing.T) {
		v := 1
		ts := Timestamp{}
		err := ts.Scan(v)
		assert.NotNil(err)
		assert.Equal(err.Error(), "Not a protobuf Timestamp")
	})
	t.Run("invalid time", func(t *testing.T) {
		v := time.Unix(maxValidSeconds, 0)
		ts := Timestamp{}
		err := ts.Scan(v)
		assert.NotNil(err)
		assert.Equal(err.Error(), "error converting the timestamp: timestamp: seconds:253402300800 after 10000-01-01")
	})
}

const maxValidSeconds = 253402300800

func utcDate(year, month, day int) time.Time {
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}
