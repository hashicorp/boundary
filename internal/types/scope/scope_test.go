// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scope

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		testName   string
		resource   resource.Type
		wantScopes []Type
		wantErr    error
	}{
		{
			testName:   "Account",
			resource:   resource.Account,
			wantScopes: []Type{Global, Org},
		},
		{
			testName:   "Alias",
			resource:   resource.Alias,
			wantScopes: []Type{Global},
		},
		{
			testName: "All",
			resource: resource.All,
			wantErr:  errors.New(context.Background(), errors.InvalidParameter, "scope.AllowedIn", "resource type '*' is not supported"),
		},
		{
			testName:   "AuthMethod",
			resource:   resource.AuthMethod,
			wantScopes: []Type{Global, Org},
		},
		{
			testName:   "AuthToken",
			resource:   resource.AuthToken,
			wantScopes: []Type{Global, Org},
		},
		{
			testName:   "AppToken",
			resource:   resource.AppToken,
			wantScopes: []Type{Global, Org},
		},
		{
			testName:   "Billing",
			resource:   resource.Billing,
			wantScopes: []Type{Global},
		},
		{
			testName:   "CredentialLibrary",
			resource:   resource.CredentialLibrary,
			wantScopes: []Type{Project},
		},
		{
			testName:   "Credential",
			resource:   resource.Credential,
			wantScopes: []Type{Project},
		},
		{
			testName:   "CredentialStore",
			resource:   resource.CredentialStore,
			wantScopes: []Type{Project},
		},
		{
			testName:   "Group",
			resource:   resource.Group,
			wantScopes: []Type{Global, Org, Project},
		},
		{
			testName:   "HostCatalog",
			resource:   resource.HostCatalog,
			wantScopes: []Type{Project},
		},
		{
			testName:   "HostSet",
			resource:   resource.HostSet,
			wantScopes: []Type{Project},
		},
		{
			testName:   "Host",
			resource:   resource.Host,
			wantScopes: []Type{Project},
		},
		{
			testName:   "ManagedGroup",
			resource:   resource.ManagedGroup,
			wantScopes: []Type{Global, Org},
		},
		{
			testName:   "Policy",
			resource:   resource.Policy,
			wantScopes: []Type{Global, Org},
		},
		{
			testName:   "Role",
			resource:   resource.Role,
			wantScopes: []Type{Global, Org, Project},
		},
		{
			testName:   "Scope",
			resource:   resource.Scope,
			wantScopes: []Type{Global, Org, Project},
		},
		{
			testName:   "SessionRecording",
			resource:   resource.SessionRecording,
			wantScopes: []Type{Global, Org},
		},
		{
			testName:   "Session",
			resource:   resource.Session,
			wantScopes: []Type{Project},
		},
		{
			testName:   "StorageBucket",
			resource:   resource.StorageBucket,
			wantScopes: []Type{Global, Org},
		},
		{
			testName:   "Target",
			resource:   resource.Target,
			wantScopes: []Type{Project},
		},
		{
			testName: "Unknown",
			resource: resource.Unknown,
			wantErr:  errors.New(context.Background(), errors.InvalidParameter, "scope.AllowedIn", "unknown resource type"),
		},
		{
			testName:   "User",
			resource:   resource.User,
			wantScopes: []Type{Global, Org},
		},
		{
			testName:   "Worker",
			resource:   resource.Worker,
			wantScopes: []Type{Global},
		},
		{
			testName: "Invalid resource type",
			resource: 999,
			wantErr:  errors.New(context.Background(), errors.InvalidParameter, "scope.AllowedIn", "invalid resource type: 999"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			scopes, err := AllowedIn(context.Background(), tt.resource)
			if tt.wantErr != nil {
				require.Error(t, err)
				require.EqualError(t, err, tt.wantErr.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantScopes, scopes)
		})
	}
}
