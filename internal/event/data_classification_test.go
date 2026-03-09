// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataClassification_Validate(t *testing.T) {
	tests := []struct {
		name            string
		c               DataClassification
		wantIsErr       error
		wantErrContains string
	}{
		{name: "invalid........", c: "invalid", wantIsErr: ErrInvalidParameter, wantErrContains: "invalid data classification 'invalid'"},
		{name: "invalid-unknown", c: UnknownClassification, wantIsErr: ErrInvalidParameter, wantErrContains: "invalid data classification 'unknown'"},
		{name: "valid-sensitive", c: SensitiveClassification},
		{name: "valid-public...", c: PublicClassification},
		{name: "valid-secret...", c: SecretClassification},
		{name: "valid-unknown..", c: SecretClassification},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.c.Validate()
			if tt.wantIsErr != nil {
				require.Error(err)
				assert.ErrorIs(err, tt.wantIsErr)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}
