// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testAppTokenInput struct {
	tokenId    string
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
				tokenId:    globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: true,
			wantQuery:   grantsForTokenGlobalOrgProjectResourcesRecursiveQuery,
		},
		{
			name: "global token grants for recursive requests for global org resources",
			input: testAppTokenInput{
				tokenId:    globals.GlobalPrefix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForTokenGlobalOrgResourcesRecursiveQuery,
		},
		{
			name: "org token grants for recursive requests for global org project resources",
			input: testAppTokenInput{
				tokenId:    globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: true,
			wantQuery:   grantsForTokenOrgGlobalOrgProjectResourcesRecursiveQuery,
		},
		{
			name: "org token grants for recursive requests for global org resources",
			input: testAppTokenInput{
				tokenId:    globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForTokenOrgGlobalOrgResourcesRecursiveQuery,
		},
		{
			name: "org token grants for recursive requests for project resources",
			input: testAppTokenInput{
				tokenId:    globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForTokenOrgProjectResourcesRecursiveQuery,
		},
		{
			name: "project token grants for recursive requests",
			input: testAppTokenInput{
				tokenId:    globals.ProjectPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForTokenProjectResourcesRecursiveQuery,
		},
		{
			name: "global token grants for non-recursive requests for global org project resource",
			input: testAppTokenInput{
				tokenId:    globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			wantQuery:   grantsForTokenGlobalOrgProjectResourcesQuery,
		},
		{
			name: "global token grants for non-recursive requests for global org resources",
			input: testAppTokenInput{
				tokenId:    globals.GlobalPrefix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForTokenGlobalOrgResourcesQuery,
		},
		{
			name: "org token grants for non-recursive requests for global org project resources",
			input: testAppTokenInput{
				tokenId:    globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			wantQuery:   grantsForTokenOrgGlobalOrgProjectResourcesQuery,
		},
		{
			name: "org token grants for non-recursive requests for global org resources",
			input: testAppTokenInput{
				tokenId:    globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForTokenOrgGlobalOrgResourcesQuery,
		},
		{
			name: "org token grants for non-recursive requests for project resources",
			input: testAppTokenInput{
				tokenId:    globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForTokenOrgProjectResourcesQuery,
		},
		{
			name: "project token grants for non-recursive requests",
			input: testAppTokenInput{
				tokenId:    globals.ProjectPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForTokenProjectResourcesQuery,
		},
		{
			name: "invalid request scope id",
			input: testAppTokenInput{
				tokenId:    globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: "invalid-scope-id",
			},
			isRecursive: false,
			errorMsg:    "request scope must be global scope, an org scope, or a project scope",
		},
		{
			name: "invalid resource type",
			input: testAppTokenInput{
				tokenId:    globals.GlobalPrefix,
				resource:   []resource.Type{resource.Unknown},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "resource type cannot be unknown",
		},
		{
			name: "missing resource type",
			input: testAppTokenInput{
				tokenId:    globals.GlobalPrefix,
				resource:   nil,
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "missing resource type",
		},
		{
			name: "resource type 'all'",
			input: testAppTokenInput{
				tokenId:    globals.GlobalPrefix,
				resource:   []resource.Type{resource.All},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "resource type cannot be all",
		},
		{
			name: "missing request scope id",
			input: testAppTokenInput{
				tokenId:    globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: "",
			},
			isRecursive: false,
			errorMsg:    "missing request scope id",
		},
		{
			name: "missing token id",
			input: testAppTokenInput{
				tokenId:    "",
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "missing token id",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			gotQuery, err := repo.resolveAppTokenQuery(ctx, tc.input.tokenId, tc.input.resource, tc.input.reqScopeId, tc.isRecursive)
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

func TestGrantsForTokenGlobalRecursive(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)

	// Create test scopes - this will create global, org, and project scopes
	_, _ = TestScopes(t, repo)

	// Create a role in the global scope that will have grants
	globalRole := TestRole(t, conn, globals.GlobalPrefix)

	// Add grants to the global role - these are the grants that should be returned
	// for a global token requesting scope resources recursively
	testGrants := []string{
		"ids=*;type=scope;actions=list,read",
		// TODO: Add more grants here
	}

	_, err := repo.AddRoleGrants(ctx, globalRole.PublicId, 1, testGrants)
	require.NoError(t, err)

	// // Create a token in the global scope
	// // TODO: TestAppToken
	// token := TestAppToken(t, conn, globals.GlobalPrefix, nil)

	// // Assign the global role to the token
	// // TODO: AssignRoleToToken
	// err = repo.AssignRoleToToken(ctx, token.PublicId, globalRole.PublicId, globals.GlobalPrefix)
	// require.NoError(t, err)

	// // Once the actual SQL queries are implemented, this should return the grants
	// gt, err := repo.GrantsForToken(ctx, token.PublicId, []resource.Type{resource.Scope}, globals.GlobalPrefix, WithRecursive(true))
	// if err != nil {
	// 	t.Logf("Expected error due to undefined query constants: %v", err)
	// 	return
	// }

	// require.NoError(t, err)
	// require.NotNil(t, gt)
	// fmt.Printf("Grants returned: %+v\n", gt)

	// TODO: Assertions to verify that the returned grants match the testGrants
}
