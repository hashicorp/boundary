// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeliveryGuarantee_validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		g               DeliveryGuarantee
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:            "invalid",
			g:               "invalid",
			wantErrIs:       ErrInvalidParameter,
			wantErrContains: "not a valid delivery guarantee",
		},
		{
			name: "BestEffort",
			g:    BestEffort,
		},
		{
			name: "Default",
			g:    DefaultDeliveryGuarantee,
		},
		{
			name: "Enforced",
			g:    Enforced,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.g.validate()
			if tt.wantErrIs != nil {
				require.Error(err)
				assert.ErrorIs(err, tt.wantErrIs)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}
