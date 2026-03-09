// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterOperation_Validate(t *testing.T) {
	tests := []struct {
		name            string
		fop             FilterOperation
		wantIsErr       error
		wantErrContains string
	}{
		{name: "invalid........", fop: "invalid", wantIsErr: ErrInvalidParameter, wantErrContains: "invalid filter operation 'invalid'"},
		{name: "invalid-unknown", fop: UnknownOperation, wantIsErr: ErrInvalidParameter, wantErrContains: "invalid filter operation 'unknown'"},
		{name: "valid-sensitive", fop: RedactOperation},
		{name: "valid-public...", fop: EncryptOperation},
		{name: "valid-secret...", fop: HmacSha256Operation},
		{name: "valid-unknown..", fop: NoOperation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.fop.Validate()
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

func TestDefaultAuditFilterOperation(t *testing.T) {
	assert := assert.New(t)
	got := DefaultAuditFilterOperations()
	want := AuditFilterOperations{
		SecretClassification:    RedactOperation,
		SensitiveClassification: RedactOperation,
	}
	assert.Equal(want, got)
}
