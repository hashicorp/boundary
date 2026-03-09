// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultAuditConfig(t *testing.T) {
	assert := assert.New(t)
	got := DefaultAuditConfig()
	want := &AuditConfig{
		FilterOverrides: DefaultAuditFilterOperations(),
	}
	assert.Equal(want, got)
}

func TestAuditConfig_Validate(t *testing.T) {
	tests := []struct {
		name            string
		ac              *AuditConfig
		wantIsError     error
		wantErrContains string
	}{
		{
			name: "invalid-classification-override",
			ac: &AuditConfig{
				FilterOverrides: AuditFilterOperations{
					"invalid-classification": RedactOperation,
				},
			},
			wantIsError:     ErrInvalidParameter,
			wantErrContains: "invalid filter override classification (invalid-classification)",
		},
		{
			name: "invalid-operation-override",
			ac: &AuditConfig{
				FilterOverrides: AuditFilterOperations{
					SensitiveClassification: "invalid-operation",
				},
			},
			wantIsError:     ErrInvalidParameter,
			wantErrContains: "invalid filter override operation (invalid-operation)",
		},
		{
			name: "valid-default",
			ac:   DefaultAuditConfig(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			err := tt.ac.Validate()
			if tt.wantIsError != nil {
				require.Error(err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
		})
	}
}

func TestNewAuditConfig(t *testing.T) {
	wrapper := testWrapper(t)
	filterOps := AuditFilterOperations{
		SensitiveClassification: EncryptOperation,
		SecretClassification:    EncryptOperation,
	}
	tests := []struct {
		name            string
		opts            []Option
		want            *AuditConfig
		wantIsError     error
		wantErrContains string
	}{
		{
			name: "valid-default",
			want: DefaultAuditConfig(),
		},
		{
			name: "valid-with-all-opts",
			opts: []Option{WithAuditWrapper(wrapper), WithFilterOperations(filterOps)},
			want: &AuditConfig{
				FilterOverrides: filterOps,
				wrapper:         wrapper,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := NewAuditConfig(tt.opts...)
			if tt.wantIsError != nil {
				require.Error(err)
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}
