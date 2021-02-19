package handlers

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestNewFilter_everythingMatchesEmpty(t *testing.T) {
	f, err := NewFilter("")
	require.NoError(t, err)
	for _, v := range []interface{} {
		nil,
		"foo",
		"",
		1,
		-1,
		map[string]string{},
		[]string{"foo"},
		[]int(nil),
		(*filterItem)(nil),
		struct{foo string}{foo: "foo"},
		filterItem{Item: struct{foo string}{foo: "foo"}},
	}{
		b, err := f.Match(v)
		assert.NoError(t, err, "Trying to match %v", v)
		assert.True(t, b, "Trying to match %v", v)
	}
}

func TestNewFilter(t *testing.T) {
	cases := []struct {
		name string
		filter string
		fErr bool
		in interface{}
		match bool
		mErr bool
	} {
		{
			name: "bad format",
			filter: `random strings that dont match a format`,
			fErr: true,
		},
		{
			name: "no leading /item",
			filter: `""=="foo"`,
			in: "foo",
			mErr: true,
		},
		{
			name: "simple string",
			filter: `"/item"=="foo"`,
			in: "foo",
			match: true,
		},
		{
			name: "struct",
			filter: `"/item/id"=="foo"`,
			in: struct{
				ID string `json:"id"`
			}{ID: "foo"},
			match: true,
		},
		{
			name: "doesnt match struct fields",
			filter: `"/item/name"=="foo"`,
			in: struct{
				ID string `json:"id"`
			}{ID: "foo"},
			mErr: true,
		},
		{
			name: "proto well known types",
			filter: `"/item/id"=="foo"`,
			in: struct{
				ID *wrapperspb.StringValue `json:"id"`
			}{ID: wrapperspb.String("foo")},
			match: true,
		},
		{
			name: "pointer include proto well known type structure",
			filter: `"/item/id/value"=="foo"`,
			in: struct{
				ID *wrapperspb.StringValue `json:"id"`
			}{ID: wrapperspb.String("foo")},
			mErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := NewFilter(tc.filter)
			if tc.fErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			m, err := f.Match(tc.in)
			if tc.mErr {
				require.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.match, m)
		})
	}
}

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
