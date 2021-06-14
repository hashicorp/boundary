package node

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewEventWrapper(t *testing.T) {

	testWrapper := TestWrapper(t)

	tests := []struct {
		name            string
		wrapper         wrapping.Wrapper
		eventId         string
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing wrapper",
			eventId:         "test-id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "mssing wrapper",
		},
		{
			name:            "missing eventId",
			wrapper:         testWrapper,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "mssing event id",
		},
		{
			name:    "success",
			wrapper: testWrapper,
			eventId: "test-id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewEventWrapper(tt.wrapper, tt.eventId)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err %q and got %q", tt.wantErrMatch, err.Error())
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.Equal(derivedKeyId(derivedKeyPurposeEvent, tt.wrapper.KeyID(), tt.eventId), got.KeyID())
		})
	}

}
