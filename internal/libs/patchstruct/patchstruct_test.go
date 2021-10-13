package patchstruct

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPatch(t *testing.T) {
	cases := []struct {
		name     string
		dst      *structpb.Struct
		src      *structpb.Struct
		expected *structpb.Struct
	}{
		{
			name: "merge",
			dst: mustStruct(map[string]interface{}{
				"foo": "bar",
			}),
			src: mustStruct(map[string]interface{}{
				"baz": "qux",
			}),
			expected: mustStruct(map[string]interface{}{
				"foo": "bar",
				"baz": "qux",
			}),
		},
		{
			name: "overwrite",
			dst: mustStruct(map[string]interface{}{
				"foo": "bar",
			}),
			src: mustStruct(map[string]interface{}{
				"foo": "baz",
			}),
			expected: mustStruct(map[string]interface{}{
				"foo": "baz",
			}),
		},
		{
			name: "delete",
			dst: mustStruct(map[string]interface{}{
				"foo": "bar",
				"baz": "qux",
			}),
			src: mustStruct(map[string]interface{}{
				"baz": nil,
			}),
			expected: mustStruct(map[string]interface{}{
				"foo": "bar",
			}),
		},
		{
			name: "recursive",
			dst: mustStruct(map[string]interface{}{
				"nested": map[string]interface{}{
					"a": "b",
				},
				"foo": "bar",
			}),
			src: mustStruct(map[string]interface{}{
				"nested": map[string]interface{}{
					"c": "d",
				},
			}),
			expected: mustStruct(map[string]interface{}{
				"nested": map[string]interface{}{
					"a": "b",
					"c": "d",
				},
				"foo": "bar",
			}),
		},
		{
			name: "overwrite with map in src",
			dst: mustStruct(map[string]interface{}{
				"foo": "bar",
			}),
			src: mustStruct(map[string]interface{}{
				"foo": map[string]interface{}{
					"a": "b",
				},
			}),
			expected: mustStruct(map[string]interface{}{
				"foo": map[string]interface{}{
					"a": "b",
				},
			}),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			dst, src := tc.dst, tc.src
			actual := Patch(dst, src)
			require.Equal(tc.expected, actual)
			require.Equal(tc.dst, dst)
			require.Equal(tc.src, src)
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
