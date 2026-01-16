// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/stretchr/testify/assert"
)

type unknownMapper int

func (u unknownMapper) clone() MappingOverride { return u }
func (u unknownMapper) setLibraryId(_ string)  {}
func (u unknownMapper) sanitize()              {}

var _ MappingOverride = unknownMapper(0)

func TestValidMappingOverrides(t *testing.T) {
	tests := []struct {
		m    MappingOverride
		ct   globals.CredentialType
		want bool
	}{
		{
			m:    nil,
			ct:   "invalid",
			want: true,
		},
		{
			m:    nil,
			ct:   globals.UnspecifiedCredentialType,
			want: true,
		},
		{
			m:    nil,
			ct:   globals.UsernamePasswordCredentialType,
			want: true,
		},
		{
			m:    nil,
			ct:   globals.UsernamePasswordDomainCredentialType,
			want: true,
		},
		{
			m:    nil,
			ct:   globals.PasswordCredentialType,
			want: true,
		},
		{
			m:    unknownMapper(1),
			ct:   globals.UnspecifiedCredentialType,
			want: false,
		},
		{
			m:    unknownMapper(1),
			ct:   globals.UsernamePasswordCredentialType,
			want: false,
		},
		{
			m:    unknownMapper(1),
			ct:   globals.UsernamePasswordDomainCredentialType,
			want: false,
		},
		{
			m:    unknownMapper(1),
			ct:   globals.PasswordCredentialType,
			want: false,
		},
		{
			m:    allocUsernamePasswordOverride(),
			ct:   globals.UnspecifiedCredentialType,
			want: false,
		},
		{
			m:    allocUsernamePasswordOverride(),
			ct:   globals.UsernamePasswordCredentialType,
			want: true,
		},
		{
			m:    allocUsernamePasswordDomainOverride(),
			ct:   globals.UnspecifiedCredentialType,
			want: false,
		},
		{
			m:    allocUsernamePasswordDomainOverride(),
			ct:   globals.UsernamePasswordDomainCredentialType,
			want: true,
		},
		{
			m:    allocPasswordOverride(),
			ct:   globals.UnspecifiedCredentialType,
			want: false,
		},
		{
			m:    allocPasswordOverride(),
			ct:   globals.PasswordCredentialType,
			want: true,
		},
		{
			m:    allocSshPrivateKeyOverride(),
			ct:   globals.UnspecifiedCredentialType,
			want: false,
		},
		{
			m:    allocSshPrivateKeyOverride(),
			ct:   globals.SshPrivateKeyCredentialType,
			want: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("%T-%s", tt.m, tt.ct), func(t *testing.T) {
			got := validMappingOverride(tt.m, tt.ct)
			assert.Equal(t, tt.want, got)
		})
	}
}
