package patchstruct

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type testCase struct {
	name     string
	dst      map[string]interface{}
	src      map[string]interface{}
	expected map[string]interface{}
}

var testCases = []testCase{
	{
		name: "merge",
		dst: map[string]interface{}{
			"foo": "bar",
		},
		src: map[string]interface{}{
			"baz": "qux",
		},
		expected: map[string]interface{}{
			"foo": "bar",
			"baz": "qux",
		},
	},
	{
		name: "overwrite",
		dst: map[string]interface{}{
			"foo": "bar",
		},
		src: map[string]interface{}{
			"foo": "baz",
		},
		expected: map[string]interface{}{
			"foo": "baz",
		},
	},
	{
		name: "delete",
		dst: map[string]interface{}{
			"foo": "bar",
			"baz": "qux",
		},
		src: map[string]interface{}{
			"baz": nil,
		},
		expected: map[string]interface{}{
			"foo": "bar",
		},
	},
	{
		name: "recursive",
		dst: map[string]interface{}{
			"nested": map[string]interface{}{
				"a": "b",
			},
			"foo": "bar",
		},
		src: map[string]interface{}{
			"nested": map[string]interface{}{
				"c": "d",
			},
		},
		expected: map[string]interface{}{
			"nested": map[string]interface{}{
				"a": "b",
				"c": "d",
			},
			"foo": "bar",
		},
	},
	{
		name: "overwrite with map in src",
		dst: map[string]interface{}{
			"foo": "bar",
		},
		src: map[string]interface{}{
			"foo": map[string]interface{}{
				"a": "b",
			},
		},
		expected: map[string]interface{}{
			"foo": map[string]interface{}{
				"a": "b",
			},
		},
	},
	{
		name: "nil src",
		dst: map[string]interface{}{
			"foo": "bar",
		},
		src: nil,
		expected: map[string]interface{}{
			"foo": "bar",
		},
	},
	{
		name: "nil dst",
		dst:  nil,
		src: map[string]interface{}{
			"foo": "bar",
		},
		expected: map[string]interface{}{
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
			require.Equal(mustStruct(tc.expected), actual)
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
	t.Run("dst", func(t *testing.T) {
		require := require.New(t)
		_, err := PatchBytes([]byte("foo"), nil)
		require.EqualError(err, "error reading destination data: proto: cannot parse invalid wire-format data")
	})
	t.Run("src", func(t *testing.T) {
		require := require.New(t)
		_, err := PatchBytes(nil, []byte("foo"))
		require.EqualError(err, "error reading source data: proto: cannot parse invalid wire-format data")
	})
}

func mustStruct(in map[string]interface{}) *structpb.Struct {
	out, err := structpb.NewStruct(in)
	if err != nil {
		panic(err)
	}

	return out
}

func mustMarshal(in map[string]interface{}) []byte {
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
