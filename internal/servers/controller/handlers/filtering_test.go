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
		assert.True(t, f.Match(v), "Trying to match %v", v)
	}
}

func TestNewFilter(t *testing.T) {
	type embedded struct {
		Name string `json:"name"`
	}
	type multiLevel struct {
		E *embedded `json:"e"`
	}
	cases := []struct {
		name string
		filter string
		fErr bool
		in interface{}
		match bool
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
			match: false,
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
			match: false,
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
			match: false,
		},
		{
			name: "multi level struct",
			filter: `"/item/e/name"=="foo"`,
			in: multiLevel{E: &embedded{Name: "foo"}},
			match: true,
		},
		{
			name: "multi level struct",
			filter: `"/item/e/name"=="foo"`,
			in: multiLevel{E: nil},
			match: false,
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
			assert.Equal(t, tc.match, f.Match(tc.in))
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
