package base

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlagSet_StringSliceMapVar(t *testing.T) {
	t.Parallel()
	target := make(map[string][]string, 1)
	sliceMapVal := &stringSliceMapValue{
		hidden: false,
		target: &target,
	}

	tests := []struct {
		name            string
		setString       string
		wantErrContains string
	}{
		{
			name:      "key-value",
			setString: "key=value",
		},
		{
			name:      "many-values",
			setString: "key=v1,v2,v3,v4,v5",
		},
		{
			name:      "duplicate-values",
			setString: "k1=v1,v1",
			// this case passes here and errors at worker client
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

			err := sliceMapVal.Set(tt.setString)
			if tt.wantErrContains != "" {
				assert.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
		})
	}
}
