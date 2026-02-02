// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testListPageSize      = 10
	testListSmallPageSize = 2
)

var (
	// filterNothingFilterFunc does not filter out any tokens
	filterNothingFilterFunc = func(_ context.Context, appt *AppToken) (bool, error) {
		return true, nil
	}

	// filterOutInactiveFunc filters out inactive (revoked, expired, stale) tokens
	filterOutInactiveFunc = func(_ context.Context, appt *AppToken) (bool, error) {
		return appt.IsActive(), nil
	}
)

func TestList(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)

	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})

	// Create test data
	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithName("org1"), iam.WithDescription("Test Org 1"))
	globalUser := iam.TestUser(t, iamRepo, globals.GlobalPrefix)
	org1User := iam.TestUser(t, iamRepo, org1.PublicId)
	org2, proj2 := iam.TestScopes(t, iamRepo, iam.WithName("org2"), iam.WithDescription("Test Org 2"))
	org2User := iam.TestUser(t, iamRepo, org2.PublicId)

	var globalAppTokens, org1AppTokens, proj1AppTokens, org2AppTokens, proj2AppTokens, allAppTokens []*AppToken
	for range 5 {
		globalAppToken := TestCreateAppToken(t, repo, &AppToken{
			ScopeId:         globals.GlobalPrefix,
			CreatedByUserId: globalUser.PublicId,
			Permissions: []AppTokenPermission{
				{
					Label:         "test",
					Grants:        []string{"ids=*;type=scope;actions=list,read"},
					GrantedScopes: []string{globals.GrantScopeThis},
				},
			},
		})
		org1AppToken := TestCreateAppToken(t, repo, &AppToken{
			ScopeId:         org1.PublicId,
			CreatedByUserId: org1User.PublicId,
			Permissions: []AppTokenPermission{
				{
					Label:         "test",
					Grants:        []string{"ids=*;type=scope;actions=list,read"},
					GrantedScopes: []string{globals.GrantScopeThis},
				},
			},
		})
		proj1AppToken := TestCreateAppToken(t, repo, &AppToken{
			ScopeId:         proj1.PublicId,
			CreatedByUserId: org1User.PublicId,
			Permissions: []AppTokenPermission{
				{
					Label:         "test",
					Grants:        []string{"ids=*;type=target;actions=list,read"},
					GrantedScopes: []string{globals.GrantScopeThis},
				},
			},
		})
		org2AppToken := TestCreateAppToken(t, repo, &AppToken{
			ScopeId:         org2.PublicId,
			CreatedByUserId: org2User.PublicId,
			Permissions: []AppTokenPermission{
				{
					Label:         "test",
					Grants:        []string{"ids=*;type=scope;actions=list,read"},
					GrantedScopes: []string{globals.GrantScopeThis},
				},
			},
		})
		proj2AppToken := TestCreateAppToken(t, repo, &AppToken{
			ScopeId:         proj2.PublicId,
			CreatedByUserId: org2User.PublicId,
			Permissions: []AppTokenPermission{
				{
					Label:         "test",
					Grants:        []string{"ids=*;type=target;actions=list,read"},
					GrantedScopes: []string{globals.GrantScopeThis},
				},
			},
		})

		globalAppTokens = append(globalAppTokens, globalAppToken)
		org1AppTokens = append(org1AppTokens, org1AppToken)
		proj1AppTokens = append(proj1AppTokens, proj1AppToken)
		org2AppTokens = append(org2AppTokens, org2AppToken)
		proj2AppTokens = append(proj2AppTokens, proj2AppToken)
		allAppTokens = append(allAppTokens, globalAppToken, org1AppToken, proj1AppToken, org2AppToken, proj2AppToken)
	}

	// Validation Tests

	t.Run("List validation", func(t *testing.T) {
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := List(
				ctx,
				[]byte(""),
				testListPageSize,
				filterNothingFilterFunc,
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.List: missing grants hash: parameter violation")
		})

		t.Run("invalid page size", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

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

		t.Run("missing filter func", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := List(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				nil,
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.List: missing filter item callback: parameter violation")
		})

		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := List(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				nil,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.List: missing repo: parameter violation")
		})

		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := List(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				repo,
				nil,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.List: missing scope ids: parameter violation")
		})

		t.Run("empty scope ids", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := List(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				repo,
				[]string{},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.List: missing scope ids: parameter violation")
		})
	})

	t.Run("ListPage validation", func(t *testing.T) {
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListPage(
				ctx,
				[]byte(""),
				testListPageSize,
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
			ctx := t.Context()

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
			ctx := t.Context()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
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
			ctx := t.Context()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
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
			ctx := t.Context()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
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
			ctx := t.Context()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				nil,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: missing scope ids: parameter violation")
		})

		t.Run("empty scope ids", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				[]string{},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListPage: missing scope ids: parameter violation")
		})

		t.Run("invalid resource type in token", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
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
			ctx := t.Context()

			_, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
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
			ctx := t.Context()
			assert, require := assert.New(t), require.New(t)

			// There are 25 total tokens created in the test setup above.
			// We'll page through them 10 at a time, for a total of 3 pages.

			firstPageResp, err := List(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				repo,
				[]string{globals.GlobalPrefix, org1.PublicId, proj1.PublicId, org2.PublicId, proj2.PublicId},
			)
			require.NoError(err)
			require.NotNil(firstPageResp)
			assert.Equal(testListPageSize, len(firstPageResp.Items))
			assert.NotNil(firstPageResp.ListToken)
			pt, ok := firstPageResp.ListToken.Subtype.(*listtoken.PaginationToken)
			assert.True(ok)
			assert.NotNil(pt)

			secondPageResp, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				firstPageResp.ListToken,
				repo,
				[]string{globals.GlobalPrefix, org1.PublicId, proj1.PublicId, org2.PublicId, proj2.PublicId},
			)
			require.NoError(err)
			require.NotNil(secondPageResp)
			assert.Equal(testListPageSize, len(secondPageResp.Items))
			pt, ok = secondPageResp.ListToken.Subtype.(*listtoken.PaginationToken)
			assert.True(ok)
			assert.NotNil(pt)

			thirdPageResp, err := ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
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
				testListPageSize,
				filterNothingFilterFunc,
				thirdPageResp.ListToken,
				repo,
				[]string{globals.GlobalPrefix, org1.PublicId, proj1.PublicId, org2.PublicId, proj2.PublicId},
			)
			require.NotNil(err)
			assert.Contains(err.Error(), "token did not have a pagination token component")
		})
	})

	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefresh(
				ctx,
				[]byte(""),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefresh: missing grants hash: parameter violation")
		})

		t.Run("invalid page size", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefresh(
				ctx,
				[]byte("test_grants_hash"),
				0,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefresh: page size must be at least 1: parameter violation")
		})

		t.Run("missing filter func", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefresh(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				nil,
				&listtoken.Token{},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefresh: missing filter item callback: parameter violation")
		})

		t.Run("missing token", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefresh(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				nil,
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefresh: missing token: parameter violation")
		})

		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefresh(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				nil,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefresh: missing repo: parameter violation")
		})

		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefresh(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				nil,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefresh: missing scope ids: parameter violation")
		})

		t.Run("empty scope ids", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefresh(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				[]string{},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefresh: missing scope ids: parameter violation")
		})

		t.Run("invalid resource type in token", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefresh(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{ResourceType: resource.AuthToken},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefresh: token did not have an app token resource type: parameter violation")
		})

		t.Run("invalid subtype in token", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefresh(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{ResourceType: resource.AppToken, Subtype: nil},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefresh: token did not have a start-refresh token component: parameter violation")
		})
	})

	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefreshPage(
				ctx,
				[]byte(""),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefreshPage: missing grants hash: parameter violation")
		})

		t.Run("invalid page size", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefreshPage(
				ctx,
				[]byte("test_grants_hash"),
				0,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefreshPage: page size must be at least 1: parameter violation")
		})

		t.Run("missing filter func", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefreshPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				nil,
				&listtoken.Token{},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefreshPage: missing filter item callback: parameter violation")
		})

		t.Run("missing token", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefreshPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				nil,
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefreshPage: missing token: parameter violation")
		})

		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefreshPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				nil,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefreshPage: missing repo: parameter violation")
		})

		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefreshPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				nil,
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefreshPage: missing scope ids: parameter violation")
		})

		t.Run("empty scope ids", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefreshPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{},
				repo,
				[]string{},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefreshPage: missing scope ids: parameter violation")
		})

		t.Run("invalid resource type in token", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefreshPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{ResourceType: resource.AuthToken},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefreshPage: token did not have an app token resource type: parameter violation")
		})

		t.Run("invalid subtype in token", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			_, err := ListRefreshPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterNothingFilterFunc,
				&listtoken.Token{ResourceType: resource.AppToken, Subtype: nil},
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "apptoken.ListRefreshPage: token did not have a refresh token component: parameter violation")
		})
	})

	// Functional Tests

	t.Run("simple listing with pagination", func(t *testing.T) {
		testCases := []struct {
			name         string
			withScopeIds []string
			pageSize     int
			wantTokens   []*AppToken
		}{
			{
				name:         "list global tokens",
				withScopeIds: []string{globals.GlobalPrefix},
				pageSize:     testListPageSize,
				wantTokens:   globalAppTokens,
			},
			{
				name:         "list org1 tokens",
				withScopeIds: []string{org1.PublicId},
				pageSize:     testListPageSize,
				wantTokens:   org1AppTokens,
			},
			{
				name:         "list proj1 tokens",
				withScopeIds: []string{proj1.PublicId},
				pageSize:     testListPageSize,
				wantTokens:   proj1AppTokens,
			},
			{
				name:         "list all org tokens",
				withScopeIds: []string{org1.PublicId, org2.PublicId},
				pageSize:     testListPageSize,
				wantTokens:   append(org1AppTokens, org2AppTokens...),
			},
			{
				name:         "list all proj tokens",
				withScopeIds: []string{proj1.PublicId, proj2.PublicId},
				pageSize:     5,
				wantTokens:   append(proj1AppTokens, proj2AppTokens...),
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
				pageSize:   testListPageSize,
				wantTokens: allAppTokens,
			},
			{
				name:         "list with no matching scopes",
				withScopeIds: []string{"nonexistent_scope"},
				pageSize:     testListPageSize,
				wantTokens:   []*AppToken{},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				ctx := t.Context()
				assert, require := assert.New(t), require.New(t)

				resp, err := List(
					ctx,
					[]byte("test_grants_hash"),
					tc.pageSize,
					filterNothingFilterFunc,
					repo,
					tc.withScopeIds,
				)
				require.NoError(err)
				require.NotNil(resp)

				// Page through the rest of the tokens
				retrievedTokens := resp.Items
				nextToken := resp.ListToken
				for nextToken != nil {
					if _, ok := nextToken.Subtype.(*listtoken.PaginationToken); !ok {
						break
					}
					resp, err = ListPage(
						ctx,
						[]byte("test_grants_hash"),
						tc.pageSize,
						filterNothingFilterFunc,
						nextToken,
						repo,
						tc.withScopeIds,
					)
					require.NoError(err)
					require.NotNil(resp)
					retrievedTokens = append(retrievedTokens, resp.Items...)
					nextToken = resp.ListToken
				}

				// Verify expected number of tokens retrieved after paging
				assert.Equal(len(tc.wantTokens), len(retrievedTokens))

				// Verify that all expected tokens are present (order not guaranteed)
				for _, wantToken := range tc.wantTokens {
					found := false
					for _, gotToken := range retrievedTokens {
						if wantToken.PublicId == gotToken.PublicId && wantToken.ScopeId == gotToken.ScopeId {
							found = true
							break
						}
					}
					assert.True(found)
				}
			})
		}
	})

	t.Run("listing with aggressive filtering", func(t *testing.T) {
		t.Run("filter out tokens", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
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
				testListPageSize,
				filterOutOrg2Func,
				repo,
				[]string{org1.PublicId, org2.PublicId},
			)
			require.NoError(err)
			require.NotNil(resp)
			assert.Equal(5, len(resp.Items)) // Only respond with org1 tokens
		})

		t.Run("filter out inactive tokens", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			assert, require := assert.New(t), require.New(t)

			// Create a new org to avoid interference from other tests
			inactiveOrg, _ := iam.TestScopes(t, iamRepo, iam.WithName("inactive-org"), iam.WithDescription("Inactive Org"))
			inactiveOrgUser := iam.TestUser(t, iamRepo, inactiveOrg.PublicId)

			// Create a new token in the new org
			inactiveToken := TestCreateAppToken(t, repo, &AppToken{
				ScopeId:         inactiveOrg.PublicId,
				CreatedByUserId: inactiveOrgUser.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"ids=*;type=scope;actions=list,read"},
						GrantedScopes: []string{globals.GrantScopeThis},
					},
				},
			})

			resp, err := List(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterOutInactiveFunc,
				repo,
				[]string{globals.GlobalPrefix, inactiveOrg.PublicId},
			)
			require.NoError(err)
			require.NotNil(resp)
			assert.Equal(6, len(resp.Items)) // globalAppTokens (5) + inactiveToken (1)

			// Revoke
			tempTestRevokeAppToken(t, repo, inactiveToken.PublicId, inactiveOrg.PublicId)

			// List again and only find the original 5 active tokens
			resp, err = List(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterOutInactiveFunc,
				repo,
				[]string{globals.GlobalPrefix, inactiveOrg.PublicId},
			)
			require.NoError(err)
			require.NotNil(resp)
			assert.Equal(5, len(resp.Items)) // globalAppTokens (5)

			// Clean up - delete revoked token
			tempTestDeleteAppToken(t, repo, inactiveToken.PublicId, inactiveOrg.PublicId)
		})

		t.Run("filter with error", func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			errorFilterFunc := func(_ context.Context, _ *AppToken) (bool, error) {
				return false, fmt.Errorf("intentional filter error")
			}

			_, err := List(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				errorFilterFunc,
				repo,
				[]string{globals.GlobalPrefix},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "intentional filter error")
		})
	})

	t.Run("listing with refresh", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		assert, require := assert.New(t), require.New(t)

		// Create isolated scope and user to avoid interference from other tests
		listRefreshOrg, _ := iam.TestScopes(t, iamRepo, iam.WithName("list-refresh-org"), iam.WithDescription("List Refresh Org"))
		listRefreshUser := iam.TestUser(t, iamRepo, listRefreshOrg.PublicId)

		// Create ten initial tokens
		var tokensToBeRefreshed []*AppToken
		for range 10 {
			token := TestCreateAppToken(t, repo, &AppToken{
				ScopeId:         listRefreshOrg.PublicId,
				CreatedByUserId: listRefreshUser.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"ids=*;type=scope;actions=list,read"},
						GrantedScopes: []string{globals.GrantScopeThis},
					},
				},
			})
			tokensToBeRefreshed = append(tokensToBeRefreshed, token)
		}
		require.Equal(testListPageSize, len(tokensToBeRefreshed))

		// Initial list to get a start refresh token
		firstResp, err := List(
			ctx,
			[]byte("test_grants_hash"),
			testListPageSize,
			filterNothingFilterFunc,
			repo,
			[]string{listRefreshOrg.PublicId},
		)
		require.NoError(err)
		require.NotNil(firstResp)
		require.NotNil(firstResp.ListToken)
		startRefreshToken, ok := firstResp.ListToken.Subtype.(*listtoken.StartRefreshToken)
		require.True(ok)
		require.NotNil(startRefreshToken)

		time.Sleep(500 * time.Millisecond)

		// Refresh with no changes - expect no items returned
		emptyRefreshResp, err := ListRefresh(
			ctx,
			[]byte("test_grants_hash"),
			testListPageSize,
			filterNothingFilterFunc,
			firstResp.ListToken,
			repo,
			[]string{listRefreshOrg.PublicId},
		)
		require.NoError(err)
		require.NotNil(emptyRefreshResp)
		assert.Equal(0, len(emptyRefreshResp.Items))

		time.Sleep(500 * time.Millisecond)

		// Update two tokens
		testUpdateAppToken(t, repo, tokensToBeRefreshed[3].PublicId, listRefreshOrg.PublicId, map[string]any{"name": "updated-token1-name", "update_time": timestamp.New(timestamp.Now().AsTime())})
		testUpdateAppToken(t, repo, tokensToBeRefreshed[4].PublicId, listRefreshOrg.PublicId, map[string]any{"approximate_last_access_time": timestamp.New(timestamp.Now().Timestamp.AsTime()), "update_time": timestamp.New(timestamp.Now().AsTime())})

		// Now do a refresh list, expecting to find the two updated tokens
		refreshResp, err := ListRefresh(
			ctx,
			[]byte("test_grants_hash"),
			testListPageSize,
			filterNothingFilterFunc,
			emptyRefreshResp.ListToken,
			repo,
			[]string{listRefreshOrg.PublicId},
		)
		require.NoError(err)
		require.NotNil(refreshResp)
		assert.Equal(2, len(refreshResp.Items))
		for _, token := range refreshResp.Items {
			assert.Contains([]string{tokensToBeRefreshed[3].PublicId, tokensToBeRefreshed[4].PublicId}, token.PublicId)
		}

		// Clean up - delete created tokens
		for _, token := range tokensToBeRefreshed {
			tempTestDeleteAppToken(t, repo, token.PublicId, listRefreshOrg.PublicId)
		}
	})

	t.Run("listing with refresh pagination and filtering/deletions", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		assert, require := assert.New(t), require.New(t)
		sqlDb, err := conn.SqlDB(ctx)
		require.NoError(err)

		// Create isolated scope and user to avoid interference from other tests
		refreshOrg, refreshProj := iam.TestScopes(t, iamRepo, iam.WithName("refresh-org"), iam.WithDescription("Refresh Org"))
		refreshUser := iam.TestUser(t, iamRepo, refreshOrg.PublicId)

		// Create 12 new tokens to provide enough data to test revocation, update, deletion, and pagination
		var tokensToBeRefreshed []*AppToken
		for range 6 {
			orgToken := TestCreateAppToken(t, repo, &AppToken{
				ScopeId:         refreshOrg.PublicId,
				CreatedByUserId: refreshUser.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"ids=*;type=scope;actions=list,read"},
						GrantedScopes: []string{globals.GrantScopeThis},
					},
				},
			})
			projToken := TestCreateAppToken(t, repo, &AppToken{
				ScopeId:         refreshProj.PublicId,
				CreatedByUserId: refreshUser.PublicId,
				Permissions: []AppTokenPermission{
					{
						Label:         "test",
						Grants:        []string{"ids=*;type=target;actions=list,read"},
						GrantedScopes: []string{globals.GrantScopeThis},
					},
				},
			})
			tokensToBeRefreshed = append(tokensToBeRefreshed, orgToken, projToken)
		}
		assert.Equal(12, len(tokensToBeRefreshed))

		// Initial list to get a start refresh token
		firstResp, err := List(
			ctx,
			[]byte("test_grants_hash"),
			testListPageSize,
			filterOutInactiveFunc,
			repo,
			[]string{refreshOrg.PublicId, refreshProj.PublicId},
		)
		require.NoError(err)
		require.NotNil(firstResp)

		// Page through rest of the tokens to advance previous phase upper bound past creation time of new tokens
		initialTokens := firstResp.Items
		nextToken := firstResp.ListToken
		for nextToken != nil {
			if _, ok := nextToken.Subtype.(*listtoken.PaginationToken); !ok {
				break
			}
			firstResp, err = ListPage(
				ctx,
				[]byte("test_grants_hash"),
				testListPageSize,
				filterOutInactiveFunc,
				nextToken,
				repo,
				[]string{refreshOrg.PublicId, refreshProj.PublicId},
			)
			require.NoError(err)
			require.NotNil(firstResp)
			initialTokens = append(initialTokens, firstResp.Items...)
			nextToken = firstResp.ListToken
		}
		assert.Equal(12, len(initialTokens))

		// Wait to ensure time difference, then do a refresh list with no changes
		time.Sleep(500 * time.Millisecond)
		emptyRefreshResp, err := ListRefresh(
			ctx,
			[]byte("test_grants_hash"),
			testListPageSize,
			filterOutInactiveFunc,
			firstResp.ListToken,
			repo,
			[]string{refreshOrg.PublicId, refreshProj.PublicId},
		)
		require.NoError(err)
		require.NotNil(emptyRefreshResp)
		assert.Equal(0, len(emptyRefreshResp.Items)) // No changes yet, so no tokens returned

		// Now update, revoke, and delete some of the tokens created above
		// Ensure some variety in which tokens get which operation
		// There should be a total of 12 tokens created above
		// - 4 revoked, 4 updated, 4 deleted
		updatedTokens := make(map[string]bool)
		deletedTokens := make(map[string]bool)
		for i, token := range tokensToBeRefreshed {
			if i%3 == 0 { // i = 0,3,6,9
				// Revoke token
				tempTestRevokeAppToken(t, repo, token.PublicId, token.ScopeId)
			} else if i%2 == 0 { // i = 2,4,8,10
				// Update token name
				testUpdateAppToken(t, repo, token.PublicId, token.ScopeId, map[string]any{"name": fmt.Sprintf("updated-%s", token.PublicId), "update_time": timestamp.New(timestamp.Now().AsTime())})
				updatedTokens[token.PublicId] = true
			} else { // i = 1,5,7,11
				// TODO: Use actual delete when implemented
				// Delete token
				tempTestDeleteAppToken(t, repo, token.PublicId, token.ScopeId)
				// Additionally, we directly insert into the app_token_deleted table
				// These tokens should be excluded from the refresh results as they are considered deleted
				_, err := sqlDb.ExecContext(ctx, "INSERT INTO app_token_deleted (public_id) VALUES ($1)", token.PublicId)
				require.NoError(err)
				deletedTokens[token.PublicId] = true
			}
		}

		// Wait to ensure time difference, then do a second refresh list with updates and deletions
		time.Sleep(500 * time.Millisecond)
		refreshResp, err := ListRefresh(
			ctx,
			[]byte("test_grants_hash"),
			testListSmallPageSize,
			filterOutInactiveFunc,
			emptyRefreshResp.ListToken,
			repo,
			[]string{refreshOrg.PublicId, refreshProj.PublicId},
		)
		require.NoError(err)
		require.NotNil(refreshResp)

		// Page through the rest of the refreshed tokens
		retrievedRefreshTokens := refreshResp.Items
		retrievedDeletedIds := refreshResp.DeletedIds
		nextToken = refreshResp.ListToken
		for nextToken != nil {
			if _, ok := nextToken.Subtype.(*listtoken.RefreshToken); !ok {
				break
			}
			refreshResp, err = ListRefreshPage(
				ctx,
				[]byte("test_grants_hash"),
				testListSmallPageSize,
				filterOutInactiveFunc,
				nextToken,
				repo,
				[]string{refreshOrg.PublicId, refreshProj.PublicId},
			)
			require.NoError(err)
			require.NotNil(refreshResp)
			retrievedRefreshTokens = append(retrievedRefreshTokens, refreshResp.Items...)
			retrievedDeletedIds = append(retrievedDeletedIds, refreshResp.DeletedIds...)
			nextToken = refreshResp.ListToken
		}

		// Expect to find only the 4 updated tokens
		assert.Equal(4, len(retrievedRefreshTokens))
		for _, token := range retrievedRefreshTokens {
			assert.True(strings.HasPrefix(token.Name, "updated-"))
			assert.True(updatedTokens[token.PublicId])
		}

		// Expect to find the 4 deleted tokens in the deleted ids list
		assert.Equal(4, len(retrievedDeletedIds))
		for _, id := range retrievedDeletedIds {
			assert.True(deletedTokens[id])
		}

		// Clean up remaining tokens
		for i, token := range tokensToBeRefreshed {
			if i%3 == 0 || i%2 == 0 { // i = 0,2,3,4,6,8,9,10
				tempTestDeleteAppToken(t, repo, token.PublicId, token.ScopeId)
			}
		}
	})
}
