package node

import (
	"context"
	"reflect"
	"testing"

	"github.com/mitchellh/pointerstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMapField = "foo"

type testTaggedMap map[string]interface{}

func (t testTaggedMap) Tags() ([]PointerTag, error) {
	return []PointerTag{
		{
			Pointer:        "/" + testMapField,
			Classification: SecretClassification,
			Filter:         RedactOperation,
		},
	}, nil
}

// Test_Map is a POC test for using an EncryptFilter to filter a Taggable map.
// It is not a real solution test... just some ideas of how one might be built
func Test_Map(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	wrapper := TestWrapper(t)
	testEncryptingFilter := &EncryptFilter{
		Wrapper:  wrapper,
		HmacSalt: []byte("salt"),
		HmacInfo: []byte("info"),
	}

	m := testTaggedMap{
		"foo": "bar",
	}

	var i interface{} = m

	taggedMap, ok := i.(Taggable)
	require.Truef(ok, "should have satisfied the interface")
	if ok {

		tags, err := taggedMap.Tags()
		require.NoError(err)
		for _, pt := range tags {
			value, err := pointerstructure.Get(taggedMap, pt.Pointer)
			require.NoError(err)
			assert.Equal(value, m[testMapField])
			rv := reflect.Indirect(reflect.ValueOf(value))
			info := &tagInfo{
				Classification: pt.Classification,
				Operation:      pt.Filter,
			}
			err = testEncryptingFilter.filterValue(ctx, rv, info, withPointer(m, pt.Pointer))
			require.NoError(err)
			assert.Equal(RedactedData, m[testMapField])
		}
	}
}
