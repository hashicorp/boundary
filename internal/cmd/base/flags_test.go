// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"os"
	"testing"

	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestUint16Var(t *testing.T) {
	t.Parallel()

	target := uint16(0)

	flagSets := NewFlagSets(cli.NewMockUi())
	f := flagSets.NewFlagSet("testset")
	f.Uint16Var(&Uint16Var{
		Name:    "test_name",
		Aliases: []string{"test_alias1"},
		Usage:   "test_usage",
		Default: 1,
		Hidden:  false,
		Target:  &target,
	})
	require.Equal(t, uint16(1), target) // Should immediately default.

	// Value that overflows uint16 should error.
	err := flagSets.Parse([]string{"-test_name", "66000"})
	require.EqualError(t, err, "invalid value \"66000\" for flag -test_name: strconv.ParseUint: parsing \"66000\": value out of range")
	require.Equal(t, uint16(1), target)

	// Value that overflows uint16 (via alias) should error.
	err = flagSets.Parse([]string{"-test_alias1", "66000"})
	require.EqualError(t, err, "invalid value \"66000\" for flag -test_alias1: strconv.ParseUint: parsing \"66000\": value out of range")
	require.Equal(t, uint16(1), target)

	// Negative value should error.
	err = flagSets.Parse([]string{"-test_name", "-1"})
	require.EqualError(t, err, "invalid value \"-1\" for flag -test_name: strconv.ParseUint: parsing \"-1\": invalid syntax")
	require.Equal(t, uint16(1), target)

	// Negative value (via alias) should error.
	err = flagSets.Parse([]string{"-test_alias1", "-1"})
	require.EqualError(t, err, "invalid value \"-1\" for flag -test_alias1: strconv.ParseUint: parsing \"-1\": invalid syntax")
	require.Equal(t, uint16(1), target)

	// Valid value should be put into target.
	err = flagSets.Parse([]string{"-test_name", "123"})
	require.NoError(t, err)
	require.Equal(t, uint16(123), target)

	// Valid value (using alias) should be put into target.
	err = flagSets.Parse([]string{"-test_alias1", "456"})
	require.NoError(t, err)
	require.Equal(t, uint16(456), target)

	// Env var tests.
	envTarget := uint16(0)
	envVarName := "test_uint16_env_var"

	envFlagSets := NewFlagSets(cli.NewMockUi())
	ef := envFlagSets.NewFlagSet("env_testset")

	require.NoError(t, os.Setenv(envVarName, "66000"))
	ef.Uint16Var(&Uint16Var{
		Name:    "test_env_name1",
		Default: 1,
		EnvVar:  envVarName,
		Target:  &envTarget,
	})
	require.Equal(t, uint16(1), envTarget) // Should be set to default because env value parse will have failed.
	require.NoError(t, os.Unsetenv(envVarName))
	envTarget = uint16(0)

	require.NoError(t, os.Setenv(envVarName, "-1"))
	ef.Uint16Var(&Uint16Var{
		Name:    "test_env_name2",
		Default: 1,
		EnvVar:  envVarName,
		Target:  &envTarget,
	})
	require.Equal(t, uint16(1), envTarget) // Should be set to default because env value parse will have failed.
	require.NoError(t, os.Unsetenv(envVarName))
	envTarget = uint16(0)

	require.NoError(t, os.Setenv(envVarName, "123"))
	ef.Uint16Var(&Uint16Var{
		Name:    "test_env_name3",
		Default: 1,
		EnvVar:  envVarName,
		Target:  &envTarget,
	})
	require.Equal(t, uint16(123), envTarget) // Should be set to what was set in env.
	require.NoError(t, os.Unsetenv(envVarName))
}
