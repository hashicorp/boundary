// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
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
	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithName("org1"), iam.WithDescription("Test Org 1"))

	testCases := []struct {
		name           string
		u              *iam.User
		tokenScopeId   string
		reqScopeId     string
		grants         []string
		grantThisScope bool   // whether grants apply to the token's own scope
		grantScope     string // "descendants", "children", or "individual" (not applicable for project tokens)
		rTypes         []resource.Type
		recursive      bool
		wantErr        bool
		expectedGrants tempGrantTuples
	}{
		{
			name: "global token requesting global scope for group,scopes recursively",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=scope;actions=list,read",
				"ids=*;type=group;actions=list",
			},
			grantThisScope: true,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.Group, resource.Scope},
			tokenScopeId:   globals.GlobalPrefix,
			reqScopeId:     globals.GlobalPrefix,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       "global",
					AppTokenParentScopeId: "",
					GrantScopeId:          "descendants",
					Grant:                 "ids=*;type=group;actions=list,ids=*;type=scope;actions=list,read",
				},
			},
		},
		{
			name: "global token requesting global scope for accounts recursively",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=account;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.Account},
			tokenScopeId:   globals.GlobalPrefix,
			reqScopeId:     globals.GlobalPrefix,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       "global",
					AppTokenParentScopeId: "",
					GrantScopeId:          "descendants",
					Grant:                 "ids=*;type=account;actions=list,read",
				},
			},
		},
		{
			name: "global token requesting global scope for credential-libraries recursively",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=credential-library;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.CredentialLibrary},
			tokenScopeId:   globals.GlobalPrefix,
			reqScopeId:     globals.GlobalPrefix,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       "global",
					AppTokenParentScopeId: "",
					GrantScopeId:          "descendants",
					Grant:                 "ids=*;type=credential-library;actions=list,read",
				},
			},
		},
		{
			name: "org token requesting org scope for accounts,scope recursively",
			u:    iam.TestUser(t, iamRepo, org1.PublicId),
			grants: []string{
				"ids=*;type=account;actions=list",
				"ids=*;type=scope;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "children",
			rTypes:         []resource.Type{resource.Account, resource.Scope},
			tokenScopeId:   org1.PublicId,
			reqScopeId:     org1.PublicId,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       org1.PublicId,
					AppTokenParentScopeId: "global",
					GrantScopeId:          "children",
					Grant:                 "ids=*;type=account;actions=list,ids=*;type=scope;actions=list,read",
				},
			},
		},
		{
			name: "org token requesting org scope for auth-methods recursively",
			u:    iam.TestUser(t, iamRepo, org1.PublicId),
			grants: []string{
				"ids=*;type=auth-method;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "children",
			rTypes:         []resource.Type{resource.AuthMethod},
			tokenScopeId:   org1.PublicId,
			reqScopeId:     org1.PublicId,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       org1.PublicId,
					AppTokenParentScopeId: "global",
					GrantScopeId:          "children",
					Grant:                 "ids=*;type=auth-method;actions=list,read",
				},
			},
		},
		{
			name: "org token requesting org scope for targets recursively",
			u:    iam.TestUser(t, iamRepo, org1.PublicId),
			grants: []string{
				"ids=*;type=target;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "children",
			rTypes:         []resource.Type{resource.Target},
			tokenScopeId:   org1.PublicId,
			reqScopeId:     org1.PublicId,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       org1.PublicId,
					AppTokenParentScopeId: "global",
					GrantScopeId:          "children",
					Grant:                 "ids=*;type=target;actions=list,read",
				},
			},
		},
		{
			name: "project token requesting project scope for targets recursively",
			u:    iam.TestUser(t, iamRepo, org1.PublicId),
			grants: []string{
				"ids=*;type=host-set;actions=read",
				"ids=*;type=host;actions=list",
				"ids=*;type=target;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "",
			rTypes:         []resource.Type{resource.HostSet, resource.Host, resource.Target},
			tokenScopeId:   proj1.PublicId,
			reqScopeId:     proj1.PublicId,
			recursive:      true,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       proj1.PublicId,
					AppTokenParentScopeId: org1.PublicId,
					GrantScopeId:          "individual",
					Grant:                 "ids=*;type=host-set;actions=read,ids=*;type=host;actions=list,ids=*;type=target;actions=list,read",
				},
			},
		},
		{
			name: "project token requesting project scope for targets non-recursively",
			u:    iam.TestUser(t, iamRepo, org1.PublicId),
			grants: []string{
				"ids=*;type=target;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "",
			rTypes:         []resource.Type{resource.Target},
			tokenScopeId:   proj1.PublicId,
			reqScopeId:     proj1.PublicId,
			recursive:      false,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       proj1.PublicId,
					AppTokenParentScopeId: org1.PublicId,
					GrantScopeId:          "individual",
					Grant:                 "ids=*;type=target;actions=list,read",
				},
			},
		},
		{
			name: "global token requesting global scope for group,scopes non-recursively",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=group;actions=list",
				"ids=*;type=scope;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.Group, resource.Scope},
			tokenScopeId:   globals.GlobalPrefix,
			reqScopeId:     globals.GlobalPrefix,
			recursive:      false,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       "global",
					AppTokenParentScopeId: "",
					GrantScopeId:          "descendants",
					Grant:                 "ids=*;type=group;actions=list,ids=*;type=scope;actions=list,read",
				},
			},
		},
		{
			name: "global token requesting org scope for auth-methods non-recursively",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=auth-method;actions=list,read",
			},
			grantThisScope: false,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.AuthMethod},
			tokenScopeId:   globals.GlobalPrefix,
			reqScopeId:     org1.PublicId,
			recursive:      false,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       "global",
					AppTokenParentScopeId: "",
					GrantScopeId:          "descendants",
					Grant:                 "ids=*;type=auth-method;actions=list,read",
				},
			},
		},
		{
			name: "global token requesting project scope for targets non-recursively",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=target;actions=list,read",
			},
			grantThisScope: false,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.Target},
			tokenScopeId:   globals.GlobalPrefix,
			reqScopeId:     proj1.PublicId,
			recursive:      false,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       "global",
					AppTokenParentScopeId: "",
					GrantScopeId:          "descendants",
					Grant:                 "ids=*;type=target;actions=list,read",
				},
			},
		},
		{
			name: "org token requesting org scope for account,auth-method non-recursively",
			u:    iam.TestUser(t, iamRepo, org1.PublicId),
			grants: []string{
				"ids=*;type=account;actions=list,read",
				"ids=*;type=auth-method;actions=list",
			},
			grantThisScope: true,
			grantScope:     "children",
			rTypes:         []resource.Type{resource.Account, resource.AuthMethod},
			tokenScopeId:   org1.PublicId,
			reqScopeId:     org1.PublicId,
			recursive:      false,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       org1.PublicId,
					AppTokenParentScopeId: "global",
					GrantScopeId:          "children",
					Grant:                 "ids=*;type=account;actions=list,read,ids=*;type=auth-method;actions=list",
				},
			},
		},
		{
			name: "org token requesting project scope for host,targets non-recursively",
			u:    iam.TestUser(t, iamRepo, org1.PublicId),
			grants: []string{
				"ids=*;type=host;actions=list",
				"ids=*;type=target;actions=list,read",
			},
			grantThisScope: false,
			grantScope:     "children",
			rTypes:         []resource.Type{resource.Host, resource.Target},
			tokenScopeId:   org1.PublicId,
			reqScopeId:     proj1.PublicId,
			recursive:      false,
			wantErr:        false,
			expectedGrants: tempGrantTuples{
				{
					AppTokenScopeId:       org1.PublicId,
					AppTokenParentScopeId: "global",
					GrantScopeId:          "children",
					Grant:                 "ids=*;type=host;actions=list,ids=*;type=target;actions=list,read",
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
			tokenScopeId:   globals.GlobalPrefix,
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
			tokenScopeId:   globals.GlobalPrefix,
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
			tokenScopeId:   globals.GlobalPrefix,
			reqScopeId:     globals.GlobalPrefix,
			recursive:      true,
			wantErr:        true,
			expectedGrants: nil,
		},
		{
			name: "missing reqScopeId",
			u:    iam.TestUser(t, iamRepo, globals.GlobalPrefix),
			grants: []string{
				"ids=*;type=scope;actions=list,read",
			},
			grantThisScope: true,
			grantScope:     "descendants",
			rTypes:         []resource.Type{resource.All},
			tokenScopeId:   globals.GlobalPrefix,
			recursive:      true,
			wantErr:        true,
			expectedGrants: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			var opts []Option
			if tc.recursive {
				opts = append(opts, WithRecursive(tc.recursive))
			}

			// Create a token with the specified grants
			token := TestAppToken(t, repo, tc.tokenScopeId, tc.u, 0, nil, tc.grants, tc.grantThisScope, tc.grantScope)

			// Fetch the grants for the token
			gt, err := repo.GrantsForToken(ctx, token.PublicId, tc.rTypes, tc.reqScopeId, opts...)
			if tc.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			require.NotNil(gt)

			// Verify the returned grants match the expected grants
			require.Len(gt, len(tc.expectedGrants))
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
				assert.True(found, "expected grant not found: %+v\n%+v", expected, gt)
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
			name: "global token recursive requests for global org project resources",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: true,
			wantQuery:   grantsForGlobalTokenGlobalOrgProjectResourcesRecursiveQuery,
		},
		{
			name: "global token recursive requests for global org resources",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: true,
			wantQuery:   grantsForGlobalTokenGlobalOrgResourcesRecursiveQuery,
		},
		{
			name: "global token recursive requests for project resources",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForGlobalTokenProjectResourcesRecursiveQuery,
		},
		{
			name: "org token recursive requests for global org project resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForOrgTokenGlobalOrgProjectResourcesRecursiveQuery,
		},
		{
			name: "org token recursive requests for global org resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForOrgTokenGlobalOrgResourcesRecursiveQuery,
		},
		{
			name: "org token recursive requests for project resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForOrgTokenProjectResourcesRecursiveQuery,
		},
		{
			name: "project token recursive requests",
			input: testAppTokenInput{
				tokenScope: globals.ProjectPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: true,
			wantQuery:   grantsForProjectTokenRecursiveQuery,
		},
		{
			name: "global token non-recursive requests for global resource",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			wantQuery:   grantsForGlobalTokenGlobalRequestScopeQuery,
		},
		{
			name: "global token non-recursive requests for org resources",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.AuthMethod},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForGlobalTokenOrgRequestScopeQuery,
		},
		{
			name: "global token non-recursive requests for project resources",
			input: testAppTokenInput{
				tokenScope: globals.GlobalPrefix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForGlobalTokenProjectRequestScopeQuery,
		},
		{
			name: "org token non-recursive requests for org resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Scope, resource.Role},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForOrgTokenOrgRequestScopeQuery,
		},
		{
			name: "org token non-recursive requests for project resources",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForOrgTokenProjectRequestScopeQuery,
		},
		{
			name: "project token non-recursive requests",
			input: testAppTokenInput{
				tokenScope: globals.ProjectPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Target},
				reqScopeId: globals.ProjectPrefix + scopeSuffix,
			},
			isRecursive: false,
			wantQuery:   grantsForProjectTokenQuery,
		},
		{
			name: "invalid global request scope for org token",
			input: testAppTokenInput{
				tokenScope: globals.OrgPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "no matching query found for token scope, request scope",
		},
		{
			name: "invalid global request scope for project token",
			input: testAppTokenInput{
				tokenScope: globals.ProjectPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Billing},
				reqScopeId: globals.GlobalPrefix,
			},
			isRecursive: false,
			errorMsg:    "no matching query found for token scope, request scope",
		},
		{
			name: "invalid org request scope for project token",
			input: testAppTokenInput{
				tokenScope: globals.ProjectPrefix + scopeSuffix,
				resource:   []resource.Type{resource.Scope},
				reqScopeId: globals.OrgPrefix + scopeSuffix,
			},
			isRecursive: false,
			errorMsg:    "no matching query found for token scope, request scope",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			gotQuery, err := repo.resolveAppTokenQuery(ctx, tc.input.tokenScope, tc.input.resource, tc.input.reqScopeId, tc.isRecursive)
			if tc.errorMsg != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.errorMsg)
				return
			}
			require.NoError(err)
			assert.Equal(gotQuery, tc.wantQuery)
		})
	}
}

func TestSelectRecursiveQuery(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)

	testcases := []struct {
		name              string
		isGlobal          bool
		isOrg             bool
		isProject         bool
		resourceAllowedIn []scope.Type
		wantQuery         string
		wantErr           bool
	}{
		{
			name:              "global token with global org project resources",
			isGlobal:          true,
			isOrg:             false,
			isProject:         false,
			resourceAllowedIn: []scope.Type{scope.Global, scope.Org, scope.Project},
			wantQuery:         grantsForGlobalTokenGlobalOrgProjectResourcesRecursiveQuery,
			wantErr:           false,
		},
		{
			name:              "global token with global org resources",
			isGlobal:          true,
			isOrg:             false,
			isProject:         false,
			resourceAllowedIn: []scope.Type{scope.Global, scope.Org},
			wantQuery:         grantsForGlobalTokenGlobalOrgResourcesRecursiveQuery,
			wantErr:           false,
		},
		{
			name:              "global token with project resources",
			isGlobal:          true,
			isOrg:             false,
			isProject:         false,
			resourceAllowedIn: []scope.Type{scope.Project},
			wantQuery:         grantsForGlobalTokenProjectResourcesRecursiveQuery,
			wantErr:           false,
		},
		{
			name:              "org token with global org project resources",
			isGlobal:          false,
			isOrg:             true,
			isProject:         false,
			resourceAllowedIn: []scope.Type{scope.Global, scope.Org, scope.Project},
			wantQuery:         grantsForOrgTokenGlobalOrgProjectResourcesRecursiveQuery,
			wantErr:           false,
		},
		{
			name:              "org token with global org resources",
			isGlobal:          false,
			isOrg:             true,
			isProject:         false,
			resourceAllowedIn: []scope.Type{scope.Global, scope.Org},
			wantQuery:         grantsForOrgTokenGlobalOrgResourcesRecursiveQuery,
			wantErr:           false,
		},
		{
			name:              "org token with project resources",
			isGlobal:          false,
			isOrg:             true,
			isProject:         false,
			resourceAllowedIn: []scope.Type{scope.Project},
			wantQuery:         grantsForOrgTokenProjectResourcesRecursiveQuery,
			wantErr:           false,
		},
		{
			name:              "project token",
			isGlobal:          false,
			isOrg:             false,
			isProject:         true,
			resourceAllowedIn: []scope.Type{scope.Project},
			wantQuery:         grantsForProjectTokenRecursiveQuery,
			wantErr:           false,
		},
		{
			name:              "global token with unmatched resource allowed in",
			isGlobal:          true,
			isOrg:             false,
			isProject:         false,
			resourceAllowedIn: []scope.Type{scope.Org},
			wantQuery:         "",
			wantErr:           true,
		},
		{
			name:              "org token with unmatched resource allowed in",
			isGlobal:          false,
			isOrg:             true,
			isProject:         false,
			resourceAllowedIn: []scope.Type{scope.Org},
			wantQuery:         "",
			wantErr:           true,
		},
		{
			name:              "no token scope set",
			isGlobal:          false,
			isOrg:             false,
			isProject:         false,
			resourceAllowedIn: []scope.Type{scope.Project},
			wantQuery:         "",
			wantErr:           true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			gotQuery, err := repo.selectRecursiveQuery(ctx, tc.isGlobal, tc.isOrg, tc.isProject, tc.resourceAllowedIn)
			if tc.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), "no matching recursive query found")
				assert.Empty(gotQuery)
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantQuery, gotQuery)
		})
	}
}

func TestSelectNonRecursiveQuery(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)

	testcases := []struct {
		name         string
		isGlobal     bool
		isOrg        bool
		isProject    bool
		isReqGlobal  bool
		isReqOrg     bool
		isReqProject bool
		wantQuery    string
		wantErr      bool
	}{
		{
			name:         "global token global request",
			isGlobal:     true,
			isOrg:        false,
			isProject:    false,
			isReqGlobal:  true,
			isReqOrg:     false,
			isReqProject: false,
			wantQuery:    grantsForGlobalTokenGlobalRequestScopeQuery,
			wantErr:      false,
		},
		{
			name:         "global token org request",
			isGlobal:     true,
			isOrg:        false,
			isProject:    false,
			isReqGlobal:  false,
			isReqOrg:     true,
			isReqProject: false,
			wantQuery:    grantsForGlobalTokenOrgRequestScopeQuery,
			wantErr:      false,
		},
		{
			name:         "global token project request",
			isGlobal:     true,
			isOrg:        false,
			isProject:    false,
			isReqGlobal:  false,
			isReqOrg:     false,
			isReqProject: true,
			wantQuery:    grantsForGlobalTokenProjectRequestScopeQuery,
			wantErr:      false,
		},
		{
			name:         "org token org request",
			isGlobal:     false,
			isOrg:        true,
			isProject:    false,
			isReqGlobal:  false,
			isReqOrg:     true,
			isReqProject: false,
			wantQuery:    grantsForOrgTokenOrgRequestScopeQuery,
			wantErr:      false,
		},
		{
			name:         "org token project request",
			isGlobal:     false,
			isOrg:        true,
			isProject:    false,
			isReqGlobal:  false,
			isReqOrg:     false,
			isReqProject: true,
			wantQuery:    grantsForOrgTokenProjectRequestScopeQuery,
			wantErr:      false,
		},
		{
			name:         "project token org request",
			isGlobal:     false,
			isOrg:        false,
			isProject:    true,
			isReqGlobal:  false,
			isReqOrg:     true,
			isReqProject: false,
			wantQuery:    "",
			wantErr:      true,
		},
		{
			name:         "no token scope set",
			isGlobal:     false,
			isOrg:        false,
			isProject:    false,
			isReqGlobal:  false,
			isReqOrg:     false,
			isReqProject: false,
			wantQuery:    "",
			wantErr:      true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			gotQuery, err := repo.selectNonRecursiveQuery(ctx, tc.isGlobal, tc.isOrg, tc.isProject, tc.isReqGlobal, tc.isReqOrg, tc.isReqProject)
			if tc.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), "no matching non-recursive query found")
				assert.Empty(gotQuery)
				return
			}
			require.NoError(err)
			assert.Equal(tc.wantQuery, gotQuery)
		})
	}
}
