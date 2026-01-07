// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resource

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Resource(t *testing.T) {
	tests := []struct {
		typeString    string
		want          Type
		topLevelType  bool
		hasChildTypes bool
		parent        Type
	}{
		{
			typeString: "unknown",
			want:       Unknown,
		},
		{
			typeString:   "scope",
			want:         Scope,
			topLevelType: true,
		},
		{
			typeString:   "user",
			want:         User,
			topLevelType: true,
		},
		{
			typeString:   "group",
			want:         Group,
			topLevelType: true,
		},
		{
			typeString:   "role",
			want:         Role,
			topLevelType: true,
		},
		{
			typeString:    "auth-method",
			want:          AuthMethod,
			topLevelType:  true,
			hasChildTypes: true,
		},
		{
			typeString: "account",
			want:       Account,
			parent:     AuthMethod,
		},
		{
			typeString:   "auth-token",
			want:         AuthToken,
			topLevelType: true,
		},
		{
			typeString:   "app-token",
			want:         AppToken,
			topLevelType: true,
		},
		{
			typeString: "*",
			want:       All,
		},
		{
			typeString:    "host-catalog",
			want:          HostCatalog,
			topLevelType:  true,
			hasChildTypes: true,
		},
		{
			typeString: "host-set",
			want:       HostSet,
			parent:     HostCatalog,
		},
		{
			typeString: "host",
			want:       Host,
			parent:     HostCatalog,
		},
		{
			typeString:   "target",
			want:         Target,
			topLevelType: true,
		},
		{
			typeString: "controller",
			want:       Controller,
		},
		{
			typeString:   "worker",
			want:         Worker,
			topLevelType: true,
		},
		{
			typeString:   "alias",
			want:         Alias,
			topLevelType: true,
		},
		{
			typeString:   "session",
			want:         Session,
			topLevelType: true,
		},
		{
			typeString: "managed-group",
			want:       ManagedGroup,
			parent:     AuthMethod,
		},
		{
			typeString:   "storage-bucket",
			want:         StorageBucket,
			topLevelType: true,
		},
		{
			typeString:    "credential-store",
			want:          CredentialStore,
			topLevelType:  true,
			hasChildTypes: true,
		},
		{
			typeString: "credential-library",
			want:       CredentialLibrary,
			parent:     CredentialStore,
		},
		{
			typeString: "credential",
			want:       Credential,
			parent:     CredentialStore,
		},
		{
			typeString:   "policy",
			want:         Policy,
			topLevelType: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.typeString, func(t *testing.T) {
			assert.Equalf(t, tt.want, Map[tt.typeString], "unexpected type for %s", tt.typeString)
			assert.Equalf(t, tt.typeString, tt.want.String(), "unexpected string for %s", tt.typeString)
			assert.Equalf(t, tt.topLevelType, tt.want.TopLevelType(), "unexpected top level type types for %s", tt.typeString)
			assert.Equalf(t, tt.hasChildTypes, tt.want.HasChildTypes(), "unexpected has child types for %s", tt.typeString)
			parent := tt.want.Parent()
			if tt.parent == Unknown {
				assert.Equal(t, tt.want, parent)
			} else {
				assert.Equal(t, tt.parent, parent)
			}
		})
	}
}
