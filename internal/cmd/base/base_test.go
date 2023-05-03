// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package base

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReparseArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  []string
		output []string
	}{
		{
			name:   "empty",
			input:  []string{},
			output: []string{},
		},
		{
			name:   "no-bools",
			input:  []string{"-foo", "bar", "-num", "5", "-attr", "yo=noid"},
			output: []string{"-foo", "bar", "-num", "5", "-attr", "yo=noid"},
		},
		{
			name:   "bool-at-end-default-type",
			input:  []string{"-attr", "this=that=thot", "-num", "5", "-bool"},
			output: []string{"-attr", "this=that=thot", "-num", "5", "-bool"},
		},
		{
			name:   "bool-in-middle-default-type",
			input:  []string{"-attr", "this=that=thot", "-bool", "-num", "5"},
			output: []string{"-attr", "this=that=thot", "-bool", "-num", "5"},
		},
		{
			name:   "bool-in-middle-true",
			input:  []string{"-attr", "this=that=thot", "-bool", "true", "-num", "5"},
			output: []string{"-attr", "this=that=thot", "-bool=true", "-num", "5"},
		},
		{
			name:   "bool-in-middle-false",
			input:  []string{"-attr", "this=that=thot", "-bool", "false", "-num", "5"},
			output: []string{"-attr", "this=that=thot", "-bool=false", "-num", "5"},
		},
		{
			name:   "bool-in-middle-something-else",
			input:  []string{"-attr", "this=that=thot", "-bool", "null", "-num", "5"},
			output: []string{"-attr", "this=that=thot", "-bool", "null", "-num", "5"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.output, reparseArgs(tt.input))
		})
	}
}
