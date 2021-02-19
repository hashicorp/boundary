package handlers

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestWellKnownTypeFilterHook(t *testing.T) {
	conversations := map[interface{}]interface{}{
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
	for in, out := range conversations {
		assert.Equal(t, reflect.ValueOf(out).Interface(), wellKnownTypeFilterHook(reflect.ValueOf(in)).Interface())
	}
}
