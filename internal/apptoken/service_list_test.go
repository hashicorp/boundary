// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	ctx := t.Context()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)

	// Create test data
	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithName("org1"), iam.WithDescription("Test Org 1"))
	globalUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
	org1User := iam.TestUser(t, iamRepo, org1.PublicId)
	org2, proj2 := iam.TestScopes(t, iamRepo, iam.WithName("org2"), iam.WithDescription("Test Org 2"))
	org2User := iam.TestUser(t, iamRepo, org2.PublicId)

	var globalAppTokens, org1AppTokens, proj1AppTokens, org2AppTokens, proj2AppTokens, allAppTokens []*AppToken
	for range 5 {
		globalAppToken := TestAppToken(t, repo, globals.GlobalPrefix, []string{"ids=*;type=scope;actions=list,read"}, globalUser, true, "individual")
		org1AppToken := TestAppToken(t, repo, org1.PublicId, []string{"ids=*;type=scope;actions=list,read"}, org1User, true, "individual")
		proj1AppToken := TestAppToken(t, repo, proj1.PublicId, []string{"ids=*;type=target;actions=list,read"}, org1User, true, "individual")
		org2AppToken := TestAppToken(t, repo, org2.PublicId, []string{"ids=*;type=scope;actions=list,read"}, org2User, true, "individual")
		proj2AppToken := TestAppToken(t, repo, proj2.PublicId, []string{"ids=*;type=target;actions=list,read"}, org2User, true, "individual")

		globalAppTokens = append(globalAppTokens, globalAppToken)
		org1AppTokens = append(org1AppTokens, org1AppToken)
		proj1AppTokens = append(proj1AppTokens, proj1AppToken)
		org2AppTokens = append(org2AppTokens, org2AppToken)
		proj2AppTokens = append(proj2AppTokens, proj2AppToken)
		allAppTokens = append(allAppTokens, globalAppToken, org1AppToken, proj1AppToken, org2AppToken, proj2AppToken)
	}

	// Filter functions
	filterNothingFilterFunc := func(_ context.Context, appt *AppToken) (bool, error) {
		return true, nil
	}
	filterOutInactiveFunc := func(_ context.Context, appt *AppToken) (bool, error) {
		return appt.IsActive(), nil
	}

	t.Run("List validation", func(t *testing.T) {
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
				wantTokens:   globalAppTokens[0:5],
				wantErr:      false,
			},
			{
				name:         "list org1 tokens",
				withScopeIds: []string{org1.PublicId},
				pageSize:     10,
				wantTokens:   org1AppTokens[0:5],
				wantErr:      false,
			},
			{
				name:         "list proj1 tokens",
				withScopeIds: []string{proj1.PublicId},
				pageSize:     10,
				wantTokens:   proj1AppTokens[0:5],
				wantErr:      false,
			},
			{
				name:         "list all org tokens",
				withScopeIds: []string{org1.PublicId, org2.PublicId},
				pageSize:     10,
				wantTokens:   append(org1AppTokens[0:5], org2AppTokens[0:5]...),
				wantErr:      false,
			},
			{
				name:         "list all proj tokens",
				withScopeIds: []string{proj1.PublicId, proj2.PublicId},
				pageSize:     10,
				wantTokens:   append(proj1AppTokens[0:5], proj2AppTokens[0:5]...),
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
				pageSize:   30,
				wantTokens: allAppTokens,
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
					filterNothingFilterFunc,
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
			assert.Equal(5, len(resp.Items)) // Only respond with org1 tokens
		})

		t.Run("filter out inactive tokens", func(t *testing.T) {
			// This test is intentionally not run in parallel because it modifies shared state
			assert, require := assert.New(t), require.New(t)

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
			assert.Equal(6, len(resp.Items)) // globalAppTokens (5) + globalTokenToBeInactive (1)

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
			assert.Equal(5, len(resp.Items)) // globalAppTokens (5)

			// Delete the revoked token to clean up
			tempTestDeleteAppToken(t, repo, globalTokenToBeInactive.PublicId, globals.GlobalPrefix)
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
				filterNothingFilterFunc,
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
				filterNothingFilterFunc,
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
				filterNothingFilterFunc,
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.List: page size must be at least 1: parameter violation")
		})
	})

	t.Run("ListPage validation", func(t *testing.T) {
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()

			_, err := ListPage(
				ctx,
				[]byte(""),
				10,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: missing grants hash: parameter violation")
		})

		t.Run("invalid page size", func(t *testing.T) {
			t.Parallel()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				0,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: page size must be at least 1: parameter violation")
		})

		t.Run("missing filter func", func(t *testing.T) {
			t.Parallel()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				10,
				nil,
				&listtoken.Token{},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: missing filter item callback: parameter violation")
		})

		t.Run("missing token", func(t *testing.T) {
			t.Parallel()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				10,
				filterNothingFilterFunc,
				nil,
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: missing token: parameter violation")
		})

		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				10,
				filterNothingFilterFunc,
				&listtoken.Token{},
				nil,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: missing repo: parameter violation")
		})

		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				10,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				nil,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: missing scope ids: parameter violation")
		})

		t.Run("invalid resource type in token", func(t *testing.T) {
			t.Parallel()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				10,
				filterNothingFilterFunc,
				&listtoken.Token{ResourceType: resource.AuthToken},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: token did not have an app token resource type: parameter violation")
		})

		t.Run("invalid subtype in token", func(t *testing.T) {
			t.Parallel()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				10,
				filterNothingFilterFunc,
				&listtoken.Token{ResourceType: resource.AppToken, Subtype: nil},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: token did not have a pagination token component: parameter violation")
		})

		t.Run("valid pagination", func(t *testing.T) {
			t.Parallel()
			assert, require := assert.New(t), require.New(t)

			// There are 25 total tokens created in the test setup above.
			// We'll page through them 10 at a time, for a total of 3 pages (10, 10, 5).
			pageSize := 10

			firstPageResp, err := List(
				ctx,
				[]byte("test_grants_hash"),
				pageSize,
				filterNothingFilterFunc,
				repo,
				[]string{globals.GlobalPrefix, org1.PublicId, proj1.PublicId, org2.PublicId, proj2.PublicId},
			)
			require.NoError(err)
			require.NotNil(firstPageResp)
			assert.Equal(pageSize, len(firstPageResp.Items))
			assert.NotNil(firstPageResp.ListToken)
			pt, ok := firstPageResp.ListToken.Subtype.(*listtoken.PaginationToken)
			assert.True(ok)
			assert.NotNil(pt)

			secondPageResp, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				pageSize,
				filterNothingFilterFunc,
				firstPageResp.ListToken,
				repo,
				[]string{globals.GlobalPrefix, org1.PublicId, proj1.PublicId, org2.PublicId, proj2.PublicId},
			)
			require.NoError(err)
			require.NotNil(secondPageResp)
			assert.Equal(pageSize, len(secondPageResp.Items))
			pt, ok = secondPageResp.ListToken.Subtype.(*listtoken.PaginationToken)
			assert.True(ok)
			assert.NotNil(pt)

			thirdPageResp, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				pageSize,
				filterNothingFilterFunc,
				secondPageResp.ListToken,
				repo,
				[]string{globals.GlobalPrefix, org1.PublicId, proj1.PublicId, org2.PublicId, proj2.PublicId},
			)
			require.NoError(err)
			require.NotNil(thirdPageResp)
			assert.Equal(5, len(thirdPageResp.Items)) // Only 5 items should be left
			assert.NotNil(thirdPageResp.ListToken)
			rt, ok := thirdPageResp.ListToken.Subtype.(*listtoken.StartRefreshToken) // Now a start refresh token
			assert.True(ok)
			assert.NotNil(rt)

			// Next page should return an error since the returned token is a start refresh token
			// and not a pagination token
			_, err = ListPage(
				ctx,
				[]byte("test_grants_hash"),
				pageSize,
				filterNothingFilterFunc,
				thirdPageResp.ListToken,
				repo,
				[]string{globals.GlobalPrefix, org1.PublicId, proj1.PublicId, org2.PublicId, proj2.PublicId},
			)
			require.NotNil(err)
			assert.Contains(err.Error(), "token did not have a pagination token component")
		})
	})
}
