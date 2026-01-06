// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKind_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		e    Kind
		want string
	}{
		{
			name: "Other",
			e:    Other,
			want: "unknown",
		},
		{
			name: "Parameter",
			e:    Parameter,
			want: "parameter violation",
		},
		{
			name: "Integrity",
			e:    Integrity,
			want: "integrity violation",
		},
		{
			name: "Search",
			e:    Search,
			want: "search issue",
		},
		{
			name: "External",
			e:    External,
			want: "external system issue",
		},
		{
			name: "VaultToken",
			e:    VaultToken,
			want: "vault token issue",
		},
		{
			name: "Configuration",
			e:    Configuration,
			want: "configuration issue",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := tt.e.String()
			assert.Equal(tt.want, got)
		})
	}
}
