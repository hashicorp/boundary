// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestPopulateAttrFlags tests common patterns we'll actually be using. Note
// that this is not an exhaustive test of the full CombinationSliceVar
// functionality, it's a bit higher level test based on what we'll actually need
// and what we'll actually have set.
func TestPopulateAttrFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		envs        [][]string
		expected    []base.CombinedSliceFlagValue
		expectedErr string
	}{
		{
			name: "strings-only",
			args: []string{"-string-attr", "foo=bar", "-string-attr", `bar="baz"`, "-string-attr", "zip=env://zip"},
			envs: [][]string{{"zip", "zap"}},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "string-attr",
					Keys:  []string{"foo"},
					Value: wrapperspb.String("bar"),
				},
				{
					Name:  "string-attr",
					Keys:  []string{"bar"},
					Value: wrapperspb.String(`"baz"`),
				},
				{
					Name:  "string-attr",
					Keys:  []string{"zip"},
					Value: wrapperspb.String("zap"),
				},
			},
		},
		{
			name: "nums-only",
			args: []string{"-num-attr", "foo=-1.2", "-num-attr", "bar=5", "-num-attr", "zip=env://zip"},
			envs: [][]string{{"zip", "5"}},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "num-attr",
					Keys:  []string{"foo"},
					Value: wrapperspb.String("-1.2"),
				},
				{
					Name:  "num-attr",
					Keys:  []string{"bar"},
					Value: wrapperspb.String("5"),
				},
				{
					Name:  "num-attr",
					Keys:  []string{"zip"},
					Value: wrapperspb.String("5"),
				},
			},
		},
		{
			name: "bools-only",
			args: []string{"-bool-attr", "foo=true", "-bool-attr", "bar=false", "-bool-attr", "zip=env://zip"},
			envs: [][]string{{"zip", "true"}},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "bool-attr",
					Keys:  []string{"foo"},
					Value: wrapperspb.String("true"),
				},
				{
					Name:  "bool-attr",
					Keys:  []string{"bar"},
					Value: wrapperspb.String("false"),
				},
				{
					Name:  "bool-attr",
					Keys:  []string{"zip"},
					Value: wrapperspb.String("true"),
				},
			},
		},
		{
			name: "key-only",
			args: []string{"-attr", "foo"},
			expected: []base.CombinedSliceFlagValue{
				{
					Name: "attr",
					Keys: []string{"foo"},
				},
			},
		},
		{
			name:        "bad-key-only-bool",
			args:        []string{"-bool-attr", "foo"},
			expectedErr: `invalid value "foo" for flag -bool-attr: key-only value provided but not supported for this flag`,
		},
		{
			name:        "bad-key-only-num",
			args:        []string{"-num-attr", "foo"},
			expectedErr: `invalid value "foo" for flag -num-attr: key-only value provided but not supported for this flag`,
		},
		{
			name:        "bad-key-only-string",
			args:        []string{"-string-attr", "foo"},
			expectedErr: `invalid value "foo" for flag -string-attr: key-only value provided but not supported for this flag`,
		},
		{
			name: "mixed",
			args: []string{"-num-attr", "foo=9820", "-string-attr", "bar=9820", "-attr", "baz=9820", "-attr", `zoom="flubber"`},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "num-attr",
					Keys:  []string{"foo"},
					Value: wrapperspb.String("9820"),
				},
				{
					Name:  "string-attr",
					Keys:  []string{"bar"},
					Value: wrapperspb.String("9820"),
				},
				{
					Name:  "attr",
					Keys:  []string{"baz"},
					Value: wrapperspb.String("9820"),
				},
				{
					Name:  "attr",
					Keys:  []string{"zoom"},
					Value: wrapperspb.String("\"flubber\""),
				},
			},
		},
		{
			name: "mixed-segments",
			args: []string{"-num-attr", "foo.bar.baz=9820", "-string-attr", "bar.baz.foo=9820", "-attr", "baz.foo.bar=9820", "-attr", "zip=env://zip"},
			envs: [][]string{{"zip", "zap"}},
			expected: []base.CombinedSliceFlagValue{
				{
					Name:  "num-attr",
					Keys:  []string{"foo", "bar", "baz"},
					Value: wrapperspb.String("9820"),
				},
				{
					Name:  "string-attr",
					Keys:  []string{"bar", "baz", "foo"},
					Value: wrapperspb.String("9820"),
				},
				{
					Name:  "attr",
					Keys:  []string{"baz", "foo", "bar"},
					Value: wrapperspb.String("9820"),
				},
				{
					Name:  "attr",
					Keys:  []string{"zip"},
					Value: wrapperspb.String("zap"),
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
					Value: wrapperspb.String("tagName eq 'application:south-seas'"),
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

			attrsInput := CombinedSliceFlagValuePopulationInput{
				FlagSet:                          f,
				FlagNames:                        flagNames[cmd],
				FullPopulationFlag:               &c.FlagAttributes,
				FullPopulationInputName:          "attributes",
				PiecewisePopulationFlag:          &c.FlagAttrs,
				PiecewisePopulationInputBaseName: "attr",
			}
			PopulateCombinedSliceFlagValue(attrsInput)

			for _, env := range tt.envs {
				require.NoError(os.Setenv(env[0], env[1]))
			}
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
		expectedMap map[string]any
		expectedErr string
	}{
		{
			name: "strings-only",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "string-%s",
					Keys:  []string{"foo"},
					Value: wrapperspb.String("bar"),
				},
				{
					Name:  "string-%s",
					Keys:  []string{"bar"},
					Value: wrapperspb.String(`"baz"`),
				},
			},
			expectedMap: map[string]any{
				"foo": "bar",
				"bar": "\"baz\"",
			},
		},
		{
			name: "nums-only",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "num-%s",
					Keys:  []string{"foo"},
					Value: wrapperspb.String("-1.2"),
				},
				{
					Name:  "num-%s",
					Keys:  []string{"bar"},
					Value: wrapperspb.String("5"),
				},
			},
			expectedMap: map[string]any{
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
					Value: wrapperspb.String("-15d.2"),
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
					Value: wrapperspb.String("-15d3"),
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
					Value: wrapperspb.String("true"),
				},
				{
					Name:  "bool-%s",
					Keys:  []string{"bar"},
					Value: wrapperspb.String("false"),
				},
			},
			expectedMap: map[string]any{
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
					Value: wrapperspb.String("t"),
				},
			},
			expectedErr: "as a bool",
		},
		{
			name: "key-only-bare",
			args: []base.CombinedSliceFlagValue{
				{
					Name: "%s",
					Keys: []string{"foo"},
				},
			},
			expectedMap: map[string]any{
				"foo": nil,
			},
		},
		{
			name: "bad-key-only-bool",
			args: []base.CombinedSliceFlagValue{
				{
					Name: "bool-%s",
					Keys: []string{"foo"},
				},
			},
			expectedErr: `requires a value`,
		},
		{
			name: "bad-key-only-num",
			args: []base.CombinedSliceFlagValue{
				{
					Name: "num-%s",
					Keys: []string{"foo"},
				},
			},
			expectedErr: `requires a value`,
		},
		{
			name: "bad-key-only-string",
			args: []base.CombinedSliceFlagValue{
				{
					Name: "string-%s",
					Keys: []string{"foo"},
				},
			},
			expectedErr: `requires a value`,
		},
		{
			name: "attr-only",
			args: []base.CombinedSliceFlagValue{
				{
					Name:  "%s",
					Keys:  []string{"b1"},
					Value: wrapperspb.String("true"),
				},
				{
					Name:  "%s",
					Keys:  []string{"b2"},
					Value: wrapperspb.String("false"),
				},
				{
					Name:  "%s",
					Keys:  []string{"s1"},
					Value: wrapperspb.String("scoopde"),
				},
				{
					Name:  "%s",
					Keys:  []string{"s2"},
					Value: wrapperspb.String("\"woo\"p"),
				},
				{
					Name:  "%s",
					Keys:  []string{"n1"},
					Value: wrapperspb.String("-1.2"),
				},
				{
					Name:  "%s",
					Keys:  []string{"n2"},
					Value: wrapperspb.String("5"),
				},
				{
					Name:  "%s",
					Keys:  []string{"a"},
					Value: wrapperspb.String(`["foo", 1.5, true, ["bar"], {"hip": "hop"}]`),
				},
				{
					Name:  "%s",
					Keys:  []string{"nil"},
					Value: wrapperspb.String("null"),
				},
				{
					Name:  "%s",
					Keys:  []string{"m"},
					Value: wrapperspb.String(`{"b": true, "n": 6, "s": "scoopde", "a": ["bar"], "m": {"hip": "hop"}}`),
				},
			},
			expectedMap: map[string]any{
				"b1": true,
				"b2": false,
				"s1": "scoopde",
				"s2": "\"woo\"p",
				"n1": float64(-1.2),
				"n2": int64(5),
				"a": []any{
					"foo",
					json.Number("1.5"),
					true,
					[]any{"bar"},
					map[string]any{"hip": "hop"},
				},
				"m": map[string]any{
					"b": true,
					"n": json.Number("6"),
					"s": "scoopde",
					"a": []any{"bar"},
					"m": map[string]any{"hip": "hop"},
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
					Value: wrapperspb.String("true"),
				},
				{
					Name:  "%s",
					Keys:  []string{"bools"},
					Value: wrapperspb.String("false"),
				},
				{
					Name:  "%s",
					Keys:  []string{"strings", "s1"},
					Value: wrapperspb.String("scoopde"),
				},
				{
					Name:  "%s",
					Keys:  []string{"strings", "s2"}, // Overwritten below
					Value: wrapperspb.String(`"woop"`),
				},
				{
					Name:  "%s",
					Keys:  []string{"numbers", "reps"},
					Value: wrapperspb.String("-1.2"),
				},
				{
					Name:  "%s",
					Keys:  []string{"numbers", "reps"},
					Value: wrapperspb.String("5"),
				},
				{
					Name:  "%s",
					Keys:  []string{"strings", "s2"}, // This will overwrite above!
					Value: wrapperspb.String("null"),
				},
			},
			expectedMap: map[string]any{
				"bools": []any{true, false},
				"strings": map[string]any{
					"s1": "scoopde",
					"s2": nil,
				},
				"numbers": map[string]any{
					"reps": []any{float64(-1.2), int64(5)},
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
				var outMap map[string]any

				args := make([]base.CombinedSliceFlagValue, 0, len(tt.args))
				for _, arg := range tt.args {
					arg.Name = fmt.Sprintf(arg.Name, typ)
					args = append(args, arg)
				}

				err := HandleAttributeFlags(c, typ, "", args, func() {}, func(in map[string]any) { outMap = in })
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

func TestNullableStringSlice(t *testing.T) {
	makeStringSlicePointer := func(in ...string) *[]string {
		return &in
	}
	tests := []struct {
		name        string
		cmd         string
		args        []string
		expected    base.StringSliceVar
		expectedErr string
	}{
		{
			name: "not-set-no-null",
			cmd:  "add-values",
			args: []string{"-val", "foobar", "-val", "barfoo", "-val", "boobaz", "-val", "bazboo"},
			expected: base.StringSliceVar{
				Target: makeStringSlicePointer("foobar", "barfoo", "boobaz", "bazboo"),
			},
		},
		{
			name:        "not-set-null",
			cmd:         "add-values",
			args:        []string{"-val", "foobar", "-val", "null", "-val", "boobaz", "-val", "bazboo"},
			expectedErr: `"null" is not an allowed value`,
		},
		{
			name: "set-no-null",
			cmd:  "set-values",
			args: []string{"-val", "foobar", "-val", "barfoo", "-val", "boobaz", "-val", "bazboo"},
			expected: base.StringSliceVar{
				Target: makeStringSlicePointer("foobar", "barfoo", "boobaz", "bazboo"),
			},
		},
		{
			name: "set-only-null",
			cmd:  "set-values",
			args: []string{"-val", "null"},
			expected: base.StringSliceVar{
				Target: makeStringSlicePointer("null"),
			},
		},
		{
			name:        "set-null-and-others-beginning",
			cmd:         "set-values",
			args:        []string{"-val", "null", "-val", "barfoo", "-val", "boobaz", "-val", "bazboo"},
			expectedErr: `"null" cannot be combined with other values`,
		},
		{
			name:        "set-null-and-others-middle",
			cmd:         "set-values",
			args:        []string{"-val", "foobar", "-val", "null", "-val", "boobaz", "-val", "bazboo"},
			expectedErr: `"null" cannot be combined with other values`,
		},
		{
			name:        "set-null-and-others-end",
			cmd:         "set-values",
			args:        []string{"-val", "foobar", "-val", "barfoo", "-val", "boobaz", "-val", "null"},
			expectedErr: `"null" cannot be combined with other values`,
		},
		{
			name: "set-null-multiple",
			cmd:  "set-values",
			args: []string{"-val", "null", "-val", "null"},
			expected: base.StringSliceVar{
				Target: makeStringSlicePointer("null"),
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
			f := flagSet.NewFlagSet("Stringsssss")
			var target []string
			ssVar := &base.StringSliceVar{
				Name:   "val",
				Target: &target,
				NullCheck: func() bool {
					return strings.HasPrefix(tt.cmd, "set-")
				},
			}
			f.StringSliceVar(ssVar)

			err := flagSet.Parse(tt.args)
			if tt.expectedErr != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.expectedErr)
				return
			}
			require.NoError(err)
			assert.Equal(*tt.expected.Target, *ssVar.Target)
		})
	}
}
