// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_extractAliasFromArgs(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantArgs  []string
		wantAlias string
	}{
		{
			name: "no-args",
		},
		{
			name:     "no-alias",
			args:     []string{"-flag", "value"},
			wantArgs: []string{"-flag", "value"},
		},
		{
			name:     "no-alias-equal-flag",
			args:     []string{"-flag=value"},
			wantArgs: []string{"-flag=value"},
		},
		{
			name:      "alias-and-flag",
			args:      []string{"alias.value", "-flag", "value"},
			wantArgs:  []string{"-flag", "value"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-and-flags",
			args:      []string{"alias.value", "-flag", "value", "-flag2", "value2"},
			wantArgs:  []string{"-flag", "value", "-flag2", "value2"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-and-equal-flag",
			args:      []string{"alias.value", "-flag=value"},
			wantArgs:  []string{"-flag=value"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-and-equal-flags",
			args:      []string{"alias.value", "-flag=value", "-flag2=value2"},
			wantArgs:  []string{"-flag=value", "-flag2=value2"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-mixed-flags",
			args:      []string{"alias.value", "-flag", "value", "-flag=value"},
			wantArgs:  []string{"-flag", "value", "-flag=value"},
			wantAlias: "alias.value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			alias, args := ExtractAliasFromArgs(tt.args)
			assert.Equal(args, tt.wantArgs)

			if tt.wantAlias != "" {
				assert.Equal(alias, tt.wantAlias)
			}
		})
	}
}
