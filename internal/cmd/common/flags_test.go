package common

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPopulateAttrFlags tests common patterns we'll actually be using. Note
// that this is not an exhaustive test of the full CombinationSliceVar
// functionality, it's a bit higher level test based on what we'll actually need
// and what we'll actually have set.
func TestPopulateAttrFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expected    []base.CombinedSliceFlagValue
		expectedErr string
	}{
		{
			name: "strings-only",
			args: []string{"-string-attr", "foo=bar", "-string-attr", `bar="baz"`},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "string-attr",
					Keys:  []string{"foo"},
					Value: "bar",
				},
				{
					Name:  "string-attr",
					Keys:  []string{"bar"},
					Value: `"baz"`,
				},
			},
		},
		{
			name: "nums-only",
			args: []string{"-num-attr", "foo=-1.2", "-num-attr", "bar=5"},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "num-attr",
					Keys:  []string{"foo"},
					Value: "-1.2",
				},
				{
					Name:  "num-attr",
					Keys:  []string{"bar"},
					Value: "5",
				},
			},
		},
		{
			name: "bools-only",
			args: []string{"-bool-attr", "foo=true", "-bool-attr", "bar=false"},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "bool-attr",
					Keys:  []string{"foo"},
					Value: "true",
				},
				{
					Name:  "bool-attr",
					Keys:  []string{"bar"},
					Value: "false",
				},
			},
		},
		{
			name: "mixed",
			args: []string{"-num-attr", "foo=9820", "-string-attr", "bar=9820", "-attr", "baz=9820"},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "num-attr",
					Keys:  []string{"foo"},
					Value: "9820",
				},
				{
					Name:  "string-attr",
					Keys:  []string{"bar"},
					Value: "9820",
				},
				{
					Name:  "attr",
					Keys:  []string{"baz"},
					Value: "9820",
				},
			},
		},
		{
			name: "mixed-segments",
			args: []string{"-num-attr", "foo.bar.baz=9820", "-string-attr", "bar.baz.foo=9820", "-attr", "baz.foo.bar=9820"},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "num-attr",
					Keys:  []string{"foo", "bar", "baz"},
					Value: "9820",
				},
				{
					Name:  "string-attr",
					Keys:  []string{"bar", "baz", "foo"},
					Value: "9820",
				},
				{
					Name:  "attr",
					Keys:  []string{"baz", "foo", "bar"},
					Value: "9820",
				},
			},
		},
		{
			name:        "bad-key-name",
			args:        []string{"-num-attr", "fo-oo=5"},
			expectedErr: "invalid value",
		},
		{
			name:        "bad-key-name-in-segment",
			args:        []string{"-num-attr", "fo.oo-o.o=5"},
			expectedErr: "invalid value",
		},
		{
			name: "colon-in-segment",
			args: []string{"-attr", "filter=tagName eq 'application:south-seas'"},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "attr",
					Keys:  []string{"filter"},
					Value: "tagName eq 'application:south-seas'",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// Note: we do the setup on each run to make sure we aren't carrying
			// state over; just like in the real CLI where each run would have
			// pristine state.
			c := new(base.Command)
			flagSet := c.FlagSet(base.FlagSetNone)
			f := flagSet.NewFlagSet("Attribute Options")
			cmd := "create"
			flagNames := map[string][]string{
				cmd: {
					"attributes",
					"attr",
					"string-attr",
					"bool-attr",
					"num-attr",
				},
			}

			PopulateAttributeFlags(c, f, flagNames, cmd)
			err := flagSet.Parse(tt.args)
			if tt.expectedErr != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.expectedErr)
				return
			}
			require.NoError(err)
			assert.Equal(tt.expected, c.FlagAttrs)
		})
	}
}

// TestHandleAttributeFlags tests the function that parses types based on
// incoming data. It assumes we're coming in with CombinedSliceFlagValues and
// validates what comes out -- whether nil func was called or the map function
// was called (and its contents).
func TestHandleAttributeFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []base.CombinedSliceFlagValue
		expectedMap map[string]interface{}
		expectedErr string
	}{
		{
			name: "strings-only",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "string-%s",
					Keys:  []string{"foo"},
					Value: "bar",
				},
				{
					Name:  "string-%s",
					Keys:  []string{"bar"},
					Value: `"baz"`,
				},
			},
			expectedMap: map[string]interface{}{
				"foo": "bar",
				"bar": "baz",
			},
		},
		{
			name: "nums-only",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "num-%s",
					Keys:  []string{"foo"},
					Value: "-1.2",
				},
				{
					Name:  "num-%s",
					Keys:  []string{"bar"},
					Value: "5",
				},
			},
			expectedMap: map[string]interface{}{
				"foo": float64(-1.2),
				"bar": int64(5),
			},
		},
		{
			name: "bad-float-num",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "num-%s",
					Keys:  []string{"foo"},
					Value: "-15d.2",
				},
			},
			expectedErr: "as a float",
		},
		{
			name: "bad-int-num",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "num-%s",
					Keys:  []string{"foo"},
					Value: "-15d3",
				},
			},
			expectedErr: "as an int",
		},
		{
			name: "bools-only",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "bool-%s",
					Keys:  []string{"foo"},
					Value: "true",
				},
				{
					Name:  "bool-%s",
					Keys:  []string{"bar"},
					Value: "false",
				},
			},
			expectedMap: map[string]interface{}{
				"foo": true,
				"bar": false,
			},
		},
		{
			name: "bad-bool",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "bool-%s",
					Keys:  []string{"foo"},
					Value: "t",
				},
			},
			expectedErr: "as a bool",
		},
		{
			name: "attr-only",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "%s",
					Keys:  []string{"b1"},
					Value: "true",
				},
				{
					Name:  "%s",
					Keys:  []string{"b2"},
					Value: "false",
				},
				{
					Name:  "%s",
					Keys:  []string{"s1"},
					Value: "scoopde",
				},
				{
					Name:  "%s",
					Keys:  []string{"s2"},
					Value: `"woop"`,
				},
				{
					Name:  "%s",
					Keys:  []string{"n1"},
					Value: "-1.2",
				},
				{
					Name:  "%s",
					Keys:  []string{"n2"},
					Value: "5",
				},
				{
					Name:  "%s",
					Keys:  []string{"a"},
					Value: `["foo", 1.5, true, ["bar"], {"hip": "hop"}]`,
				},
				{
					Name:  "%s",
					Keys:  []string{"nil"},
					Value: "null",
				},
				{
					Name:  "%s",
					Keys:  []string{"m"},
					Value: `{"b": true, "n": 6, "s": "scoopde", "a": ["bar"], "m": {"hip": "hop"}}`,
				},
			},
			expectedMap: map[string]interface{}{
				"b1": true,
				"b2": false,
				"s1": "scoopde",
				"s2": "woop",
				"n1": float64(-1.2),
				"n2": int64(5),
				"a": []interface{}{
					"foo",
					json.Number("1.5"),
					true,
					[]interface{}{"bar"},
					map[string]interface{}{"hip": "hop"},
				},
				"m": map[string]interface{}{
					"b": true,
					"n": json.Number("6"),
					"s": "scoopde",
					"a": []interface{}{"bar"},
					"m": map[string]interface{}{"hip": "hop"},
				},
				"nil": nil,
			},
		},
		{
			name: "map-array-structure",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "%s",
					Keys:  []string{"bools"},
					Value: "true",
				},
				{
					Name:  "%s",
					Keys:  []string{"bools"},
					Value: "false",
				},
				{
					Name:  "%s",
					Keys:  []string{"strings", "s1"},
					Value: "scoopde",
				},
				{
					Name:  "%s",
					Keys:  []string{"strings", "s2"},
					Value: `"woop"`,
				},
				{
					Name:  "%s",
					Keys:  []string{"numbers", "reps"},
					Value: "-1.2",
				},
				{
					Name:  "%s",
					Keys:  []string{"numbers", "reps"},
					Value: "5",
				},
				{
					Name:  "%s",
					Keys:  []string{"strings", "s2"}, // This will overwrite above!
					Value: "null",
				},
			},
			expectedMap: map[string]interface{}{
				"bools": []interface{}{true, false},
				"strings": map[string]interface{}{
					"s1": "scoopde",
					"s2": nil,
				},
				"numbers": map[string]interface{}{
					"reps": []interface{}{float64(-1.2), int64(5)},
				},
			},
		},
	}
	for _, tt := range tests {
		for _, typ := range []string{"attr", "secret"} {
			t.Run(fmt.Sprintf("%s-%s", tt.name, typ), func(t *testing.T) {
				assert, require := assert.New(t), require.New(t)

				// Note: we do the setup on each run to make sure we aren't carrying
				// state over; just like in the real CLI where each run would have
				// pristine state.
				c := new(base.Command)
				var outMap map[string]interface{}

				args := make([]base.CombinedSliceFlagValue, 0, len(tt.args))
				for _, arg := range tt.args {
					arg.Name = fmt.Sprintf(arg.Name, typ)
					args = append(args, arg)
				}

				err := HandleAttributeFlags(c, typ, "", args, func() {}, func(in map[string]interface{}) { outMap = in })
				if tt.expectedErr != "" {
					require.Error(err)
					assert.Contains(err.Error(), tt.expectedErr)
					return
				}

				require.NoError(err)
				assert.Equal(tt.expectedMap, outMap)
			})
		}
	}
}
