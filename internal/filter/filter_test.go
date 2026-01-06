// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package filter

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestWellKnownTypeFilterHook(t *testing.T) {
	t.Run("wrappers", func(t *testing.T) {
		conversions := map[any]any{
			wrapperspb.String("foo"):        "foo",
			wrapperspb.UInt64(123):          uint64(123),
			wrapperspb.Int64(123):           int64(123),
			wrapperspb.UInt32(123):          uint32(123),
			wrapperspb.Int32(123):           int32(123),
			wrapperspb.Float(123):           float32(123),
			wrapperspb.Double(123):          float64(123),
			wrapperspb.Bytes([]byte("foo")): []byte("foo"),
			wrapperspb.Bool(true):           true,
		}
		for in, out := range conversions {
			assert.Equal(t, reflect.ValueOf(out).Interface(), WellKnownTypeFilterHook(reflect.ValueOf(in)).Interface())
		}
	})
	t.Run("time", func(t *testing.T) {
		assert := assert.New(t)
		now := time.Now()
		ts := timestamppb.New(now)
		expect := reflect.ValueOf(ts.AsTime())
		actual := WellKnownTypeFilterHook(reflect.ValueOf(ts))
		assert.Equal(expect.Interface(), actual.Interface())
	})
	t.Run("struct", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		s, err := structpb.NewStruct(map[string]any{
			"name": "test",
		})
		require.NoError(err)

		expect := map[string]any{
			"name": "test",
		}
		actual := WellKnownTypeFilterHook(reflect.ValueOf(s))
		assert.Equal(expect, actual.Interface())
	})
}
