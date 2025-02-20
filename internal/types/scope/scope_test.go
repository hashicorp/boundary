// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scope

import (
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
)

func Test_Map(t *testing.T) {
	tests := []struct {
		name       string
		s          string
		want       Type
		wantPrefix string
	}{
		{
			name:       "global",
			s:          "global",
			want:       Global,
			wantPrefix: globals.GlobalPrefix,
		},
		{
			name:       "org",
			s:          "org",
			want:       Org,
			wantPrefix: globals.OrgPrefix,
		},
		{
			name:       "proj",
			s:          "project",
			want:       Project,
			wantPrefix: globals.ProjectPrefix,
		},
		{
			name:       "unknown",
			s:          "blahblah",
			want:       Unknown,
			wantPrefix: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := Map[tt.s]
			assert.Equal(tt.want, got)
			assert.Equalf(tt.wantPrefix, got.Prefix(), "unexpected prefix for %s", tt.s)
		})
	}
}

func Test_AllowedIn(t *testing.T) {
	tests := []struct {
		resource   resource.Type
		wantScopes []Type
	}{
		{
			resource:   resource.Account,
			wantScopes: []Type{Global, Org},
		},
		{
			resource:   resource.Alias,
			wantScopes: []Type{Global},
		},
		{
			resource:   resource.All,
			wantScopes: []Type{Global, Org, Project},
		},
		{
			resource:   resource.AuthMethod,
			wantScopes: []Type{Global, Org},
		},
		{
			resource:   resource.AuthToken,
			wantScopes: []Type{Global, Org},
		},
		{
			resource:   resource.Billing,
			wantScopes: []Type{Global},
		},
		{
			resource:   resource.CredentialLibrary,
			wantScopes: []Type{Project},
		},
		{
			resource:   resource.Credential,
			wantScopes: []Type{Project},
		},
		{
			resource:   resource.CredentialStore,
			wantScopes: []Type{Project},
		},
		{
			resource:   resource.Group,
			wantScopes: []Type{Global, Org, Project},
		},
		{
			resource:   resource.HostCatalog,
			wantScopes: []Type{Project},
		},
		{
			resource:   resource.HostSet,
			wantScopes: []Type{Project},
		},
		{
			resource:   resource.Host,
			wantScopes: []Type{Project},
		},
		{
			resource:   resource.ManagedGroup,
			wantScopes: []Type{Global, Org},
		},
		{
			resource:   resource.Policy,
			wantScopes: []Type{Global, Org},
		},
		{
			resource:   resource.Role,
			wantScopes: []Type{Global, Org, Project},
		},
		{
			resource:   resource.Scope,
			wantScopes: []Type{Global, Org},
		},
		{
			resource:   resource.SessionRecording,
			wantScopes: []Type{Global, Org},
		},
		{
			resource:   resource.Session,
			wantScopes: []Type{Project},
		},
		{
			resource:   resource.StorageBucket,
			wantScopes: []Type{Global, Org},
		},
		{
			resource:   resource.Target,
			wantScopes: []Type{Project},
		},
		{
			resource:   resource.Unknown,
			wantScopes: []Type{Unknown},
		},
		{
			resource:   resource.User,
			wantScopes: []Type{Global, Org},
		},
		{
			resource:   resource.Worker,
			wantScopes: []Type{Global},
		},
	}
	for _, tt := range tests {
		t.Run(tt.resource.String(), func(t *testing.T) {
			assert.Equal(t, tt.wantScopes, AllowedIn(tt.resource))
		})
	}
}
