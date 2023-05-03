// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package base

import (
	"testing"

	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlagSet_BoolVar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		setString         string
		allowUnset        bool
		def               bool
		wantPanicContains string
		wantErrContains   string
		target            func() any
		wantTarget        func() any
	}{
		{
			name:      "normal-default-false",
			setString: "",
			target: func() any {
				return new(bool)
			},
			wantTarget: func() any {
				return new(bool)
			},
		},
		{
			name:      "normal-default-true",
			setString: "",
			target: func() any {
				return new(bool)
			},
			def: true,
			wantTarget: func() any {
				b := new(bool)
				*b = true
				return b
			},
		},
		{
			name:      "normal-set-false",
			setString: "false",
			target: func() any {
				return new(bool)
			},
			def: true,
			wantTarget: func() any {
				return new(bool)
			},
		},
		{
			name:      "normal-set-true",
			setString: "true",
			target: func() any {
				return new(bool)
			},
			def: false,
			wantTarget: func() any {
				b := new(bool)
				*b = true
				return b
			},
		},
		{
			name:      "panic-nil-target",
			setString: "",
			target: func() any {
				return nil
			},
			wantPanicContains: "nil Target",
		},
		{
			name:       "panic-allow-unset-bool-pointer",
			setString:  "",
			allowUnset: true,
			target: func() any {
				return new(bool)
			},
			wantPanicContains: "has AllowUnset but not using correct type",
		},
		{
			name:      "panic-nil-bool-pointer",
			setString: "",
			target: func() any {
				return (*bool)(nil)
			},
			wantPanicContains: "Target is nil pointer",
		},
		{
			name:      "panic-no-unset-double-pointer",
			setString: "",
			target: func() any {
				b := new(bool)
				return &b
			},
			wantPanicContains: "not using AllowUnset but has type",
		},
		{
			name:      "panic-invalid-type-string",
			setString: "",
			target: func() any {
				return "foo"
			},
			wantPanicContains: "unhandled Target type",
		},
		{
			name:      "panic-invalid-type-bool",
			setString: "",
			target: func() any {
				return false
			},
			wantPanicContains: "unhandled Target type",
		},
		{
			name:      "allowunset-no-set-string",
			setString: "",
			target: func() any {
				b := new(bool)
				return &b
			},
			allowUnset: true,
			wantTarget: func() any {
				return new(*bool)
			},
		},
		{
			name:      "allowunset-set-false",
			setString: "false",
			target: func() any {
				b := new(bool)
				return &b
			},
			allowUnset: true,
			wantTarget: func() any {
				b := new(*bool)
				*b = new(bool)
				return b
			},
		},
		{
			name:      "allowunset-set-true",
			setString: "true",
			target: func() any {
				b := new(bool)
				return &b
			},
			allowUnset: true,
			wantTarget: func() any {
				b := new(*bool)
				*b = new(bool)
				**b = true
				return b
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			sets := NewFlagSets(cli.NewMockUi())
			f := sets.NewFlagSet("Testing")

			var wantTarget any
			if tt.wantTarget != nil {
				wantTarget = tt.wantTarget()
			}
			target := tt.target()
			boolVar := &BoolVar{
				Name:       "test",
				Default:    tt.def,
				Target:     target,
				AllowUnset: tt.allowUnset,
			}

			if tt.wantPanicContains != "" {
				defer func() {
					r := recover()
					require.NotNil(r)
					assert.Contains(r, tt.wantPanicContains)
				}()
			}
			f.BoolVar(boolVar)

			var args []string
			if tt.setString != "" {
				args = []string{"-test", tt.setString}
			}
			err := sets.Parse(args)
			if tt.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}

			require.NoError(err)
			assert.Equal(wantTarget, target)
		})
	}
}

func TestFlagSet_StringSliceMapVar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setString       string
		wantErrContains string
		wantTarget      map[string][]string
	}{
		{
			name:       "key-value",
			setString:  "key=value",
			wantTarget: map[string][]string{"key": {"value"}},
		},
		{
			name:       "many-values",
			setString:  "key=v1,v2,v3,v4,v5",
			wantTarget: map[string][]string{"key": {"v1", "v2", "v3", "v4", "v5"}},
		},
		{
			// this case passes here and errors at worker client
			name:       "duplicate-values",
			setString:  "k1=v1,v1",
			wantTarget: map[string][]string{"k1": {"v1", "v1"}},
		},
		{
			name:            "no-deliminator",
			setString:       "key",
			wantErrContains: "missing = in KV pair",
		},
		{
			name:            "multiple-keys",
			setString:       "k1=v1, k2=v2",
			wantErrContains: "value \"k2=v2\" is invalid",
		},
		{
			name:            "too-many-commas",
			setString:       "k1=v1,,v3?,,,,,v8",
			wantErrContains: "value \"\" is invalid",
		},
		{
			name:            "illegal-characters-key",
			setString:       "!@#$=%^&*()_",
			wantErrContains: "key \"!@#$\" is invalid",
		},
		{
			name:            "illegal-characters-value",
			setString:       "k=%^&*()_",
			wantErrContains: "value \"%^&*()_\" is invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			target := make(map[string][]string, 1)
			sliceMapVal := &stringSliceMapValue{
				hidden: false,
				target: &target,
			}

			err := sliceMapVal.Set(tt.setString)
			if tt.wantErrContains != "" {
				assert.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantTarget, *sliceMapVal.target)
		})
	}
}

func TestFlagSet_StringSliceMapVar_NullCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setStrings      []string
		wantErrContains string
		wantTarget      map[string][]string
	}{
		{
			name:       "null",
			setStrings: []string{"null"},
			wantTarget: map[string][]string{"null": nil},
			// this target is then converted to a nil value in workerscmd/func.go
		},
		{
			name:            "glass-half-null",
			setStrings:      []string{"milk=half", "null"},
			wantErrContains: `"null" cannot be combined with other values`,
		},
		{
			name:            "invalid-entry-before",
			setStrings:      []string{"the-milk-is-bad", "null"},
			wantErrContains: `missing = in KV pair: "the-milk-is-bad"`,
		},
		{
			name:            "invalid-entry-after",
			setStrings:      []string{"null", "the-milk-is-still-bad"},
			wantErrContains: `"null" cannot be combined with other values`,
		},
		{
			name:       "no-error",
			setStrings: []string{"k1=v1,v2,v3", "k2=v4,v5,v6"},
			wantTarget: map[string][]string{"k1": {"v1", "v2", "v3"}, "k2": {"v4", "v5", "v6"}},
		},
		{
			name:            "too-null",
			setStrings:      []string{"null", "null", "null"},
			wantErrContains: `"null" cannot be combined with other values`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			target := make(map[string][]string, 1)
			sliceMapVal := &stringSliceMapValue{
				hidden:    false,
				target:    &target,
				nullCheck: func() bool { return true },
			}
			var err error

			for _, s := range tt.setStrings {
				err = sliceMapVal.Set(s)
				if err != nil {
					break
				}
			}
			if tt.wantErrContains != "" {
				assert.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantTarget, *sliceMapVal.target)
		})
	}
}
