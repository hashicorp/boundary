package patchstruct

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

type testCase struct {
	name            string
	dst             map[string]interface{}
	src             map[string]interface{}
	expected        map[string]interface{}
	expectedJSONErr string
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
		expectedJSONErr: "error reading source json: unexpected end of JSON input",
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
		expectedJSONErr: "error reading destination json: unexpected end of JSON input",
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

func TestPatchJSON(t *testing.T) {
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			dst, src := mustMarshalJSON(tc.dst), mustMarshalJSON(tc.src)
			dstOrig, srcOrig := mustMarshalJSON(tc.dst), mustMarshalJSON(tc.src)
			if tc.dst == nil {
				dst = nil
				dstOrig = nil
			}
			if tc.src == nil {
				src = nil
				srcOrig = nil
			}

			actual, err := PatchJSON(dst, src)
			if tc.expectedJSONErr != "" {
				require.EqualError(err, tc.expectedJSONErr)
				return
			}

			require.NoError(err)
			require.Equal(mustMarshalJSON(tc.expected), actual)
			require.Equal(dstOrig, dst)
			require.Equal(srcOrig, src)
		})
	}
}

func mustStruct(in map[string]interface{}) *structpb.Struct {
	out, err := structpb.NewStruct(in)
	if err != nil {
		panic(err)
	}

	return out
}

func mustMarshalJSON(in map[string]interface{}) []byte {
	b, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}

	return b
}
