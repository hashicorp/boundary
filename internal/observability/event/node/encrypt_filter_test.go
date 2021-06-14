package node

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_setValue(t *testing.T) {
	t.Parallel()

	testInt := 22
	testStr := "fido"
	tests := []struct {
		name            string
		fv              reflect.Value
		newVal          string
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "not-string-or-bytes",
			fv:              reflect.ValueOf(&testInt).Elem(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "field value is not a string or []byte",
		},
		{
			name:            "not-settable",
			fv:              reflect.ValueOf(&testStr),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "unable to set value",
		},
		{
			name:   "string-with-value",
			fv:     reflect.ValueOf(&testStr).Elem(),
			newVal: "alice",
		},
		{
			name:   "empty-string",
			fv:     reflect.ValueOf(&testStr).Elem(),
			newVal: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := setValue(tt.fv, tt.newVal)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err %q and got %q", tt.wantErrMatch, err.Error())
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(fmt.Sprintf("%s", tt.fv), tt.newVal)
		})
	}

}
