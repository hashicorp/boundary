// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_extractAliasFromArgs(t *testing.T) {
	ui := &BoundaryUI{}

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
			name:      "alias-after-flag",
			args:      []string{"-flag", "value", "alias.value"},
			wantArgs:  []string{"-flag", "value"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-after-flags",
			args:      []string{"-flag", "value", "-flag2", "value2", "alias.value"},
			wantArgs:  []string{"-flag", "value", "-flag2", "value2"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-before-flag",
			args:      []string{"alias.value", "-flag", "value"},
			wantArgs:  []string{"-flag", "value"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-before-flags",
			args:      []string{"alias.value", "-flag", "value", "-flag2", "value2"},
			wantArgs:  []string{"-flag", "value", "-flag2", "value2"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-between-flags",
			args:      []string{"-flag", "value", "alias.value", "-flag2", "value2"},
			wantArgs:  []string{"-flag", "value", "-flag2", "value2"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-after-equal-flag",
			args:      []string{"-flag=value", "alias.value"},
			wantArgs:  []string{"-flag=value"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-before-equal-flag",
			args:      []string{"alias.value", "-flag=value"},
			wantArgs:  []string{"-flag=value"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-between-equal-flags",
			args:      []string{"-flag=value", "alias.value", "-flag2=value2"},
			wantArgs:  []string{"-flag=value", "-flag2=value2"},
			wantAlias: "alias.value",
		},
		{
			name:      "alias-mixed-flags",
			args:      []string{"-flag", "value", "alias.value", "-flag=value"},
			wantArgs:  []string{"-flag", "value", "-flag=value"},
			wantAlias: "alias.value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			cmd := NewCommand(ui)

			args := cmd.extractAliasFromArgs(tt.args)
			assert.Equal(args, tt.wantArgs)

			if tt.wantAlias != "" {
				assert.Equal(cmd.FlagAlias, tt.wantAlias)
			}
		})
	}
}
