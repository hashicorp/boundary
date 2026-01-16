// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_List(t *testing.T) {
	fiveDaysAgo := time.Now()
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	composedOf := session.TestSessionParams(t, conn, wrapper, iamRepo)

	listPerms := &perms.UserPermissions{
		UserId: composedOf.UserId,
		Permissions: []perms.Permission{
			{
				GrantScopeId: composedOf.ProjectId,
				Resource:     resource.Session,
				Action:       action.List,
			},
		},
	}
	var allSessions []*session.Session
	for i := 0; i < 5; i++ {
		s := session.TestSession(t, conn, wrapper, composedOf)
		allSessions = append(allSessions, s)
	}

	repo, err := session.NewRepository(ctx, rw, rw, kms, session.WithPermissions(listPerms))
	require.NoError(t, err)
	// Reverse since we read items in descending order (newest first)
	slices.Reverse(allSessions)

	// Run analyze to update postgres estimates
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpIgnoreUnexportedOpts := cmpopts.IgnoreUnexported(session.Session{}, session.State{}, timestamp.Timestamp{}, timestamppb.Timestamp{})
	cmpIgnoreFieldsOpts := cmpopts.IgnoreFields(session.Session{}, "CtCertificatePrivateKey", "CertificatePrivateKey", "KeyId", "CorrelationId")

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.List(ctx, nil, 1, filterFunc, repo, true)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.List(ctx, []byte("some hash"), 0, filterFunc, repo, true)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.List(ctx, []byte("some hash"), -1, filterFunc, repo, true)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := session.List(ctx, []byte("some hash"), 1, nil, repo, true)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.List(ctx, []byte("some hash"), 1, filterFunc, nil, true)
			require.ErrorContains(t, err, "missing repo")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, nil, 1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), 1, nil, tok, repo, true)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.ListPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, true)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, true)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "token did not have a session resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, nil, 1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), 1, nil, tok, repo, true)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.ListPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, true)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "token did not have a start-refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, true)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "token did not have a session resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListRefreshPage(ctx, nil, 1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, true)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			_, err := session.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, true)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Session, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, true)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = session.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, true)
			require.ErrorContains(t, err, "token did not have a session resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
			return true, nil
		}
		resp, err := session.List(ctx, []byte("some hash"), 1, filterFunc, repo, true)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allSessions[0], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp2, err := session.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allSessions[1], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp3, err := session.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], allSessions[2], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp4, err := session.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], allSessions[3], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp5, err := session.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], allSessions[4], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new sessions
		newS1 := session.TestSession(t, conn, wrapper, composedOf)
		newS2 := session.TestSession(t, conn, wrapper, composedOf)
		t.Cleanup(func() {
			_, err = repo.DeleteSession(ctx, newS1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSession(ctx, newS2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update target estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newS2
		resp7, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], newS2, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// Refresh again, should get newS1
		resp8, err := session.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], newS1, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// Refresh again, should get no results
		resp9, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
			return s.GetPublicId() == allSessions[1].GetPublicId() ||
				s.GetPublicId() == allSessions[len(allSessions)-1].GetPublicId(), nil
		}
		resp, err := session.List(ctx, []byte("some hash"), 1, filterFunc, repo, true)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allSessions[1], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		resp2, err := session.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, true)
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], allSessions[len(allSessions)-1], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// request a refresh, nothing should be returned
		resp3, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new allSessions
		newS1 := session.TestSession(t, conn, wrapper, composedOf)
		newS2 := session.TestSession(t, conn, wrapper, composedOf)
		newS3 := session.TestSession(t, conn, wrapper, composedOf)
		newS4 := session.TestSession(t, conn, wrapper, composedOf)
		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = repo.DeleteSession(ctx, newS1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSession(ctx, newS2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSession(ctx, newS3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSession(ctx, newS4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update target estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		filterFunc = func(_ context.Context, s *session.Session) (bool, error) {
			return s.GetPublicId() == newS3.GetPublicId() ||
				s.GetPublicId() == newS1.GetPublicId(), nil
		}
		// Refresh again, should get newS3
		resp4, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newS3, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// Refresh again, should get newS1
		resp5, err := session.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newS1, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
			return true, nil
		}
		deletedSessionId := allSessions[0].GetPublicId()
		_, err := repo.DeleteSession(ctx, deletedSessionId)
		require.NoError(t, err)
		allSessions = allSessions[1:]

		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := session.List(ctx, []byte("some hash"), 1, filterFunc, repo, true)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], allSessions[0], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// request remaining results
		resp2, err := session.ListPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, allSessions[1:], cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		deletedSessionId = allSessions[0].GetPublicId()
		_, err = repo.DeleteSession(ctx, deletedSessionId)
		require.NoError(t, err)
		allSessions = allSessions[1:]

		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, true)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedSessionId)
		require.Empty(t, resp3.Items)
	})

	t.Run("simple pagination with updated items", func(t *testing.T) {
		filterFunc := func(_ context.Context, s *session.Session) (bool, error) {
			return true, nil
		}
		resp, err := session.List(ctx, []byte("some hash"), 3, filterFunc, repo, true)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 3)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 3)
		require.Empty(t, cmp.Diff(resp.Items, allSessions, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))

		// create a new session and run analyze to update session estimate
		newSession := session.TestSession(t, conn, wrapper, composedOf)
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp2, err := session.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, true)
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], newSession, cmpIgnoreUnexportedOpts, cmpIgnoreFieldsOpts))
	})
}
