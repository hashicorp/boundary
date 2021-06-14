package node

import (
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewEventWrapper(t *testing.T) {
	t.Parallel()

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
			wantErrContains: "missing wrapper",
		},
		{
			name:            "missing eventId",
			wrapper:         testWrapper,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing event id",
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
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.Equal(derivedKeyId(derivedKeyPurposeEvent, tt.wrapper.KeyID(), tt.eventId), got.KeyID())
		})
	}

}

func Test_derivedKeyPurpose_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		k    derivedKeyPurpose
		want string
	}{
		{
			name: "unknown",
			k:    derivedKeyPurposeUnknown,
			want: "unknown",
		},
		{
			name: "event",
			k:    derivedKeyPurposeEvent,
			want: "event",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			assert.Equal(tt.want, tt.k.String())
		})
	}
}
