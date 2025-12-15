// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package patchstruct

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type testCase struct {
	name     string
	dst      map[string]any
	src      map[string]any
	expected map[string]any
}

var testCases = []testCase{
	{
		name: "merge",
		dst: map[string]any{
			"foo": "bar",
		},
		src: map[string]any{
			"baz": "qux",
		},
		expected: map[string]any{
			"foo": "bar",
			"baz": "qux",
		},
	},
	{
		name: "overwrite",
		dst: map[string]any{
			"foo": "bar",
		},
		src: map[string]any{
			"foo": "baz",
		},
		expected: map[string]any{
			"foo": "baz",
		},
	},
	{
		name: "delete",
		dst: map[string]any{
			"foo": "bar",
			"baz": "qux",
		},
		src: map[string]any{
			"baz": nil,
		},
		expected: map[string]any{
			"foo": "bar",
		},
	},
	{
		name: "recursive",
		dst: map[string]any{
			"nested": map[string]any{
				"a": "b",
			},
			"foo": "bar",
		},
		src: map[string]any{
			"nested": map[string]any{
				"c": "d",
			},
		},
		expected: map[string]any{
			"nested": map[string]any{
				"a": "b",
				"c": "d",
			},
			"foo": "bar",
		},
	},
	{
		name: "nested with nil",
		dst:  nil,
		src: map[string]any{
			"a": "b",
			"nested": map[string]any{
				"c": "d",
				"e": nil,
			},
			"f": nil,
		},
		expected: map[string]any{
			"a": "b",
			"nested": map[string]any{
				"c": "d",
			},
		},
	},
	{
		name: "overwrite with map in src",
		dst: map[string]any{
			"foo": "bar",
		},
		src: map[string]any{
			"foo": map[string]any{
				"a": "b",
			},
		},
		expected: map[string]any{
			"foo": map[string]any{
				"a": "b",
			},
		},
	},
	{
		name: "nil src",
		dst: map[string]any{
			"foo": "bar",
		},
		src:      nil,
		expected: nil,
	},
	{
		name: "nil dst",
		dst:  nil,
		src: map[string]any{
			"foo": "bar",
		},
		expected: map[string]any{
			"foo": "bar",
		},
	},
	{
		name: "nil dst with src nil value",
		dst:  nil,
		src: map[string]any{
			"foo": "bar",
			"fiz": nil,
		},
		expected: map[string]any{
			"foo": "bar",
		},
	},
}

func TestPatchStruct(t *testing.T) {
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			dst, src := mustStruct(tc.dst), mustStruct(tc.src)
			dstOrig, srcOrig := mustStruct(tc.dst), mustStruct(tc.src)
			if tc.dst == nil {
				dst = nil
				dstOrig = nil
			}
			if tc.src == nil {
				src = nil
				srcOrig = nil
			}

			actual := PatchStruct(dst, src)
			require.Empty(cmp.Diff(mustStruct(tc.expected), actual,
				cmpopts.IgnoreUnexported(structpb.Struct{}, structpb.Value{}),
				cmpopts.SortSlices(func(x, y any) bool {
					return x.(*host.IpAddress).Address < y.(*host.IpAddress).Address
				})))
			require.Equal(dstOrig, dst)
			require.Equal(srcOrig, src)
		})
	}
}

func TestPatchBytes(t *testing.T) {
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			dst, src := mustMarshal(tc.dst), mustMarshal(tc.src)

			actual, err := PatchBytes(dst, src)
			require.NoError(err)
			requireEqualEncoded(t, mustMarshal(tc.expected), actual)
		})
	}
}

func TestPatchBytesErr(t *testing.T) {
	t.Run("src", func(t *testing.T) {
		require := require.New(t)
		_, err := PatchBytes(nil, []byte("foo"))
		require.ErrorIs(err, proto.Error)
		require.True(strings.HasPrefix(err.Error(), "error reading source data: "))
	})
}

func mustStruct(in map[string]any) *structpb.Struct {
	out, err := structpb.NewStruct(in)
	if err != nil {
		panic(err)
	}

	return out
}

func mustMarshal(in map[string]any) []byte {
	b, err := proto.Marshal(mustStruct(in))
	if err != nil {
		panic(err)
	}

	return b
}

func requireEqualEncoded(t *testing.T, expected, actual []byte) {
	t.Helper()
	require := require.New(t)

	expectedpb, actualpb := new(structpb.Struct), new(structpb.Struct)

	err := proto.Unmarshal(expected, expectedpb)
	require.NoError(err)

	err = proto.Unmarshal(actual, actualpb)
	require.NoError(err)

	require.Equal(expectedpb, actualpb)
}
