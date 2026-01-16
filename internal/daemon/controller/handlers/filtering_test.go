// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestNewFilter_everythingMatchesEmpty(t *testing.T) {
	f, err := NewFilter(context.Background(), "")
	require.NoError(t, err)
	for _, v := range []any{
		nil,
		"foo",
		"",
		1,
		-1,
		map[string]string{},
		[]string{"foo"},
		[]int(nil),
		(*filterItem)(nil),
		struct{ foo string }{foo: "foo"},
		filterItem{Item: struct{ foo string }{foo: "foo"}},
	} {
		assert.True(t, f.Match(v), "Trying to match %v", v)
	}
}

func TestNewFilter(t *testing.T) {
	ctx := context.Background()
	type embedded struct {
		Name string `json:"name"`
	}
	type multiLevel struct {
		E *embedded `json:"e"`
	}
	cases := []struct {
		name   string
		filter string
		fErr   bool
		in     any
		match  bool
	}{
		{
			name:   "bad format",
			filter: `random strings that dont match a format`,
			fErr:   true,
		},
		{
			name:   "no leading /item",
			filter: `""=="foo"`,
			in:     "foo",
			match:  false,
		},
		{
			name:   "simple string",
			filter: `"/item"=="foo"`,
			in:     "foo",
			match:  true,
		},
		{
			name:   "struct",
			filter: `"/item/id"=="foo"`,
			in: struct {
				ID string `json:"id"`
			}{ID: "foo"},
			match: true,
		},
		{
			name:   "doesnt match struct fields",
			filter: `"/item/name"=="foo"`,
			in: struct {
				ID string `json:"id"`
			}{ID: "foo"},
			match: false,
		},
		{
			name:   "proto well known types",
			filter: `"/item/id"=="foo"`,
			in: struct {
				ID *wrapperspb.StringValue `json:"id"`
			}{ID: wrapperspb.String("foo")},
			match: true,
		},
		{
			name:   "pointer include proto well known type structure",
			filter: `"/item/id/value"=="foo"`,
			in: struct {
				ID *wrapperspb.StringValue `json:"id"`
			}{ID: wrapperspb.String("foo")},
			match: false,
		},
		{
			name:   "multi level struct",
			filter: `"/item/e/name"=="foo"`,
			in:     multiLevel{E: &embedded{Name: "foo"}},
			match:  true,
		},
		{
			name:   "multi level struct",
			filter: `"/item/e/name"=="foo"`,
			in:     multiLevel{E: nil},
			match:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := NewFilter(ctx, tc.filter)
			if tc.fErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.match, f.Match(tc.in))
		})
	}
}
