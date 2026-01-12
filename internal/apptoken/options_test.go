// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithRecursive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    bool
		expected bool
	}{
		{
			name:     "withRecursive true",
			input:    true,
			expected: true,
		},
		{
			name:     "withRecursive false",
			input:    false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := getOpts(WithRecursive(tt.input))
			assert.Equal(t, tt.expected, opts.withRecursive)
		})
	}
}
