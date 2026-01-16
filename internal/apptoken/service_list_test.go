// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	filterFunc := func(_ context.Context, appt *AppToken) (bool, error) {
		return true, nil
	}

	// Create test data
	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithName("org1"), iam.WithDescription("Test Org 1"))
	globalUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
	org1User := iam.TestUser(t, iamRepo, org1.PublicId)
	org2, proj2 := iam.TestScopes(t, iamRepo, iam.WithName("org2"), iam.WithDescription("Test Org 2"))
	org2User := iam.TestUser(t, iamRepo, org2.PublicId)

	globalToken1 := TestAppToken(t, repo, globals.GlobalPrefix, []string{"ids=*;type=scope;actions=list,read"}, globalUser, true, "individual")
	org1Token := TestAppToken(t, repo, org1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, org1User, true, "individual")
	proj1Token := TestAppToken(t, repo, proj1.PublicId, []string{"ids=*;type=target;actions=list,read"}, org1User, true, "individual")
	globalToken2 := TestAppToken(t, repo, globals.GlobalPrefix, []string{"ids=*;type=scope;actions=list,read"}, globalUser, true, "individual")
	org2Token := TestAppToken(t, repo, org2.PublicId, []string{"ids=*;type=scope;actions=list,read"}, org2User, true, "individual")
	proj2Token := TestAppToken(t, repo, proj2.PublicId, []string{"ids=*;type=target;actions=list,read"}, org2User, true, "individual")

	testCases := []struct {
		name           string
		withScopeIds   []string
		pageSize       int
		wantTokens     []*AppToken
		wantErr        bool
		wantErrMessage string
	}{
		{
			name:         "list global tokens",
			withScopeIds: []string{globals.GlobalPrefix},
			pageSize:     10,
			wantTokens:   []*AppToken{globalToken2, globalToken1},
			wantErr:      false,
		},
		{
			name:         "list org1 tokens",
			withScopeIds: []string{org1.PublicId},
			pageSize:     10,
			wantTokens:   []*AppToken{org1Token},
			wantErr:      false,
		},
		{
			name:         "list proj1 tokens",
			withScopeIds: []string{proj1.PublicId},
			pageSize:     10,
			wantTokens:   []*AppToken{proj1Token},
			wantErr:      false,
		},
		{
			name:         "list all org tokens",
			withScopeIds: []string{org1.PublicId, org2.PublicId},
			pageSize:     10,
			wantTokens:   []*AppToken{org2Token, org1Token},
			wantErr:      false,
		},
		{
			name: "list all tokens",
			withScopeIds: []string{
				globals.GlobalPrefix,
				org1.PublicId,
				proj1.PublicId,
				org2.PublicId,
				proj2.PublicId,
			},
			pageSize:   10,
			wantTokens: []*AppToken{globalToken2, globalToken1, org2Token, org1Token, proj2Token, proj1Token},
			wantErr:    false,
		},
		{
			name:         "list with no matching scopes",
			withScopeIds: []string{"nonexistent_scope"},
			pageSize:     10,
			wantTokens:   []*AppToken{},
			wantErr:      false,
		},
		{
			name:           "invalid missing scope ids",
			withScopeIds:   nil,
			pageSize:       10,
			wantTokens:     nil,
			wantErr:        true,
			wantErrMessage: "apptoken.List: missing scope ids: parameter violation",
		},
		{
			name:           "invalid empty scope ids",
			withScopeIds:   []string{},
			pageSize:       10,
			wantTokens:     nil,
			wantErr:        true,
			wantErrMessage: "apptoken.List: missing scope ids: parameter violation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert, require := assert.New(t), require.New(t)

			resp, err := List(
				ctx,
				[]byte("test_grants_hash"),
				tc.pageSize,
				filterFunc,
				repo,
				tc.withScopeIds,
			)
			if tc.wantErr {
				require.Error(err)
				assert.Contains(err.Error(), tc.wantErrMessage)
				return
			}
			require.NoError(err)
			require.NotNil(resp)
			assert.Equal(len(tc.wantTokens), len(resp.Items))

			// Verify that all expected tokens are present in the result
			// The order is not guaranteed, so we check presence rather than position
			for _, wantToken := range tc.wantTokens {
				found := false
				for _, gotToken := range resp.Items {
					if wantToken.PublicId == gotToken.PublicId && wantToken.ScopeId == gotToken.ScopeId {
						found = true
						break
					}
				}
				assert.True(found)
			}
		})
	}

	t.Run("filter out tokens", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)
		filterOutOrg2Func := func(_ context.Context, appt *AppToken) (bool, error) {
			// Filter out tokens associated with org2
			if appt.ScopeId == org2.PublicId {
				return false, nil
			}
			return true, nil
		}

		resp, err := List(
			ctx,
			[]byte("test_grants_hash"),
			10,
			filterOutOrg2Func,
			repo,
			[]string{org1.PublicId, org2.PublicId},
		)
		require.NoError(err)
		require.NotNil(resp)
		assert.Equal(1, len(resp.Items)) // Only respond with org1Token
		assert.Equal(org1Token.PublicId, resp.Items[0].PublicId)
	})

	t.Run("filter out inactive tokens", func(t *testing.T) {
		t.Parallel()
		assert, require := assert.New(t), require.New(t)

		filterOutInactiveFunc := func(_ context.Context, appt *AppToken) (bool, error) {
			// Filter out inactive tokens
			if !appt.IsActive() {
				return false, nil
			}
			return true, nil
		}

		// Create a new global token
		globalTokenToBeInactive := TestAppToken(t, repo, globals.GlobalPrefix, []string{"ids=*;type=scope;actions=list,read"}, globalUser, true, "individual")

		resp, err := List(
			ctx,
			[]byte("test_grants_hash"),
			10,
			filterOutInactiveFunc,
			repo,
			[]string{globals.GlobalPrefix},
		)
		require.NoError(err)
		require.NotNil(resp)
		assert.Equal(3, len(resp.Items)) // globalToken1, globalToken2, globalTokenToBeInactive

		// Revoke
		tempTestRevokeGlobalAppToken(t, repo, globalTokenToBeInactive.PublicId)

		// List again and only find the original two active tokens
		resp, err = List(
			ctx,
			[]byte("test_grants_hash"),
			10,
			filterOutInactiveFunc,
			repo,
			[]string{globals.GlobalPrefix},
		)
		require.NoError(err)
		require.NotNil(resp)
		assert.Equal(2, len(resp.Items)) // globalToken1, globalToken2
	})

	t.Run("missing filter func", func(t *testing.T) {
		t.Parallel()
		_, err := List(
			ctx,
			[]byte("test_grants_hash"),
			10,
			nil,
			repo,
			[]string{globals.GlobalPrefix},
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "apptoken.List: missing filter item callback: parameter violation")
	})

	t.Run("missing repo", func(t *testing.T) {
		t.Parallel()
		_, err := List(
			ctx,
			[]byte("test_grants_hash"),
			10,
			filterFunc,
			nil,
			[]string{globals.GlobalPrefix},
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "apptoken.List: missing repo: parameter violation")
	})

	t.Run("missing grants hash", func(t *testing.T) {
		t.Parallel()
		_, err := List(
			ctx,
			[]byte(""),
			10,
			filterFunc,
			repo,
			[]string{globals.GlobalPrefix},
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "apptoken.List: missing grants hash: parameter violation")
	})

	t.Run("invalid page size", func(t *testing.T) {
		t.Parallel()
		_, err := List(
			ctx,
			[]byte("test_grants_hash"),
			0,
			filterFunc,
			repo,
			[]string{globals.GlobalPrefix},
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "apptoken.List: page size must be at least 1: parameter violation")
	})
}
