// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package timestamp

import (
	"reflect"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TimestampValue(t *testing.T) {
	t.Parallel()
	t.Run("valid", func(t *testing.T) {
		ts := Timestamp{Timestamp: &timestamp.Timestamp{Seconds: 0, Nanos: 0}}
		v, err := ts.Value()
		require.Nil(t, err)
		assert.Equal(t, v, utcDate(1970, 1, 1))
	})
	t.Run("valid nil ts", func(t *testing.T) {
		var ts *Timestamp
		v, err := ts.Value()
		require.Nil(t, err)
		assert.Equal(t, v, nil)
	})
	t.Run("invalid ts", func(t *testing.T) {
		ts := Timestamp{Timestamp: &timestamp.Timestamp{Seconds: maxValidSeconds, Nanos: 0}}
		v, err := ts.Value()
		require.NoError(t, err)
		assert.Equal(t, v, utcDate(10000, 1, 1))
	})
	t.Run("negativeInfinity", func(t *testing.T) {
		ts := New(NegativeInfinityTS)
		v, err := ts.Value()
		require.NoError(t, err)
		assert.Equal(t, v, "-infinity")
	})
	t.Run("positiveInfinity", func(t *testing.T) {
		ts := New(PositiveInfinityTS)
		v, err := ts.Value()
		require.NoError(t, err)
		assert.Equal(t, v, "infinity")
	})
}

func Test_TimestampScan(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	t.Run("valid", func(t *testing.T) {
		v := time.Unix(0, 0)
		ts := Timestamp{}
		err := ts.Scan(v)
		require.Nil(err)
		assert.True(reflect.DeepEqual(ts.Timestamp, &timestamp.Timestamp{Seconds: 0, Nanos: 0}))
	})
	t.Run("valid default time", func(t *testing.T) {
		var v time.Time
		ts := Timestamp{}
		err := ts.Scan(v)
		require.Nil(err)
		assert.True(reflect.DeepEqual(ts.Timestamp, &timestamp.Timestamp{Seconds: -62135596800, Nanos: 0}))
	})
	t.Run("invalid type", func(t *testing.T) {
		v := 1
		ts := Timestamp{}
		err := ts.Scan(v)
		assert.True(err != nil)
		assert.Equal("Not a protobuf Timestamp", err.Error())
	})
	t.Run("invalid time", func(t *testing.T) {
		v := time.Unix(maxValidSeconds, 0)
		ts := Timestamp{}
		err := ts.Scan(v)
		require.Nil(err)
	})
	t.Run("negativeInfinity", func(t *testing.T) {
		v := "-infinity"
		ts := Timestamp{}
		err := ts.Scan(v)
		require.NoError(err)
		assert.Equal(ts.AsTime(), NegativeInfinityTS)
	})
	t.Run("positiveInfinity", func(t *testing.T) {
		v := "infinity"
		ts := Timestamp{}
		err := ts.Scan(v)
		require.NoError(err)
		assert.Equal(ts.AsTime(), PositiveInfinityTS)
	})
}

const maxValidSeconds = 253402300800

func utcDate(year, month, day int) time.Time {
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}
