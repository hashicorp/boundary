// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrantsForToken(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)

	// Create test scope hierarchy for testing grant scope behavior
	// This creates: global -> org1 -> project1
	//                      -> org2 -> project2
	org1, _ := iam.TestScopes(t, iamRepo, iam.WithName("org1"), iam.WithDescription("Test Org 1"))
	// org2, proj2 := TestScopes(t, repo, WithName("org2"), WithDescription("Test Org 2"))

	testCases := []struct {
		name           string
		u              *iam.User
		grants         []string
		grantThisScope bool   // whether grants apply to the token's own scope
		grantScope     string // "descendants", "children", or "individual" (not applicable for project tokens)
		rTypes         []resource.Type
		reqScopeId     string
		recursive      bool
		wantErr        bool
		expectedGrants tempGrantTuples
	}{
		{
			name:           "global token requesting scope resources recursively with descendants",
			u:              iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants:         []string{"ids=*;type=scope;actions=list,read"},
			grantThisScope: true,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.Scope},
			reqScopeId:     globals.GlobalPrefix,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       "global",
					AppTokenParentScopeId: "",
					GrantScopeId:          "descendants",
					Grant:                 "ids=*;type=scope;actions=list,read",
				},
			},
		},
		{
			name:           "org token requesting scope resources recursively with children",
			u:              iam.TestUser(t, iamRepo, org1.PublicId),
			grants:         []string{"ids=*;type=scope;actions=list,read"},
			grantThisScope: true,
			grantScope:     "children",
			rTypes:         []resource.Type{resource.Scope},
			reqScopeId:     org1.PublicId,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       org1.PublicId,
					AppTokenParentScopeId: "",
					GrantScopeId:          "children",
					Grant:                 "ids=*;type=scope;actions=list,read",
				},
			},
		},
		{
			name: "org token requesting auth_method resources recursively with children",
			u:    iam.TestUser(t, iamRepo, org1.PublicId),
			grants: []string{
				"ids=*;type=auth-method;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "children",
			rTypes:         []resource.Type{resource.AuthMethod},
			reqScopeId:     org1.PublicId,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       org1.PublicId,
					AppTokenParentScopeId: "",
					GrantScopeId:          "children",
					Grant:                 "ids=*;type=auth-method;actions=list,read",
				},
			},
		},
		{
			name: "org token requesting target resources recursively with children",
			u:    iam.TestUser(t, iamRepo, org1.PublicId),
			grants: []string{
				"ids=*;type=target;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "children",
			rTypes:         []resource.Type{resource.Target},
			reqScopeId:     org1.PublicId,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       org1.PublicId,
					AppTokenParentScopeId: "",
					GrantScopeId:          "children",
					Grant:                 "ids=*;type=target;actions=list,read",
				},
			},
		},
		{
			name: "missing resource type",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=scope;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "descendants",
			rTypes:         nil,
			reqScopeId:     globals.GlobalPrefix,
			recursive:      true,
			wantErr:        true,
			expectedGrants: nil,
		},
		{
			name: "unknown resource type",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=scope;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.Unknown},
			reqScopeId:     globals.GlobalPrefix,
			recursive:      true,
			wantErr:        true,
			expectedGrants: nil,
		},
		{
			name: "resource type 'all'",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=scope;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.All},
			reqScopeId:     globals.GlobalPrefix,
			recursive:      true,
			wantErr:        true,
			expectedGrants: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var opts []Option
			if tc.recursive {
				opts = append(opts, WithRecursive(tc.recursive))
			}

			// Create a token with the specified grants
			token := TestAppToken(t, repo, tc.reqScopeId, tc.grants, tc.u, tc.grantThisScope, tc.grantScope)

			// Fetch the grants for the token
			gt, err := repo.GrantsForToken(ctx, token.PublicId, tc.rTypes, tc.reqScopeId, opts...)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, gt)

			for _, expected := range tc.expectedGrants {
				found := false
				for _, actual := range gt {
					if actual.AppTokenId == token.PublicId &&
						actual.AppTokenScopeId == expected.AppTokenScopeId &&
						actual.AppTokenParentScopeId == expected.AppTokenParentScopeId &&
						actual.GrantScopeId == expected.GrantScopeId &&
						actual.Grant == expected.Grant {
						found = true
						break
					}
				}
				assert.True(t, found)
			}
		})
	}
}

type testAppTokenInput struct {
	tokenScope string
	resource   []resource.Type
	reqScopeId string
}

func TestResolveAppTokenQuery(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)

	scopeSuffix := "_12345"

	testcases := []struct {
		name        string
		input       testAppTokenInput
		isRecursive bool
		wantQuery   string
		errorMsg    string
	}{
		{
			name: "global token grants for recursive requests for global org project resources",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: true,
			wantQuery:   grantsForGlobalTokenGlobalOrgProjectResourcesRecursiveQuery,
		},
		{
			name: "global token grants for recursive requests for global org resources",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: true,
			wantQuery:   grantsForGlobalTokenGlobalOrgResourcesRecursiveQuery,
		},
		{
			name: "org token grants for recursive requests for global org project resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForOrgTokenGlobalOrgProjectResourcesRecursiveQuery,
		},
		{
			name: "org token grants for recursive requests for global org resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForOrgTokenGlobalOrgResourcesRecursiveQuery,
		},
		{
			name: "org token grants for recursive requests for project resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForOrgTokenProjectResourcesRecursiveQuery,
		},
		{
			name: "project token grants for recursive requests",
			input: testAppTokenInput{
				tokenScope: globals.ProjectPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForProjectTokenResourcesRecursiveQuery,
		},
		{
			name: "global token grants for non-recursive requests for global org project resource",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			wantQuery:   grantsForGlobalTokenGlobalOrgProjectResourcesQuery,
		},
		{
			name: "global token grants for non-recursive requests for global org resources",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			wantQuery:   grantsForGlobalTokenGlobalOrgResourcesQuery,
		},
		{
			name: "org token grants for non-recursive requests for global org project resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Scope, resource.Role},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForOrgTokenGlobalOrgResourcesQuery,
		},
		{
			name: "org token grants for non-recursive requests for global org resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForOrgTokenGlobalOrgResourcesQuery,
		},
		{
			name: "org token grants for non-recursive requests for project resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForOrgTokenProjectResourcesQuery,
		},
		{
			name: "project token grants for non-recursive requests",
			input: testAppTokenInput{
				tokenScope: globals.ProjectPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForProjectTokenResourcesQuery,
		},
		{
			name: "invalid request scope id",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: "invalid-scope-id",
			},
			isRecursive: false,
			errorMsg:    "request scope must be global scope, an org scope, or a project scope",
		},
		{
			name: "invalid resource type",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Unknown},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "resource type cannot be unknown",
		},
		{
			name: "missing resource type",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   nil,
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "missing resource type",
		},
		{
			name: "resource type 'all'",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.All},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "resource type cannot be all",
		},
		{
			name: "missing request scope id",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: "",
			},
			isRecursive: false,
			errorMsg:    "missing request scope id",
		},
		{
			name: "missing token scope",
			input: testAppTokenInput{
				tokenScope: "",
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "missing token scope",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			gotQuery, err := repo.resolveAppTokenQuery(ctx, tc.input.tokenScope, tc.input.resource, tc.input.reqScopeId, tc.isRecursive)
			if tc.errorMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, gotQuery, tc.wantQuery)
		})
	}
}
