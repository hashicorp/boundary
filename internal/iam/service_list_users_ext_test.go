// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	iamstore "github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_ListUsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	repo := iam.TestRepo(t, conn, wrapper)
	o := iam.TestOrg(t, repo)

	iamRepoFn := func() (*iam.Repository, error) {
		return repo, nil
	}
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kms)
	}
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(ctx, rw, rw, kms)
	}

	users := []*iam.User{}
	for i := 0; i < 5; i++ {
		users = append(users, iam.TestUser(t, repo, o.GetPublicId()))
	}

	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())

	// Run analyze to update user estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	requestInfo := authpb.RequestInfo{
		TokenFormat: uint32(auth.AuthTokenTypeBearer),
		PublicId:    at.GetPublicId(),
		Token:       at.GetToken(),
	}
	requestContext := context.WithValue(context.Background(), requests.ContextRequestInformationKey, &requests.RequestContext{})
	ctx = auth.NewVerifierContext(requestContext, iamRepoFn, tokenRepoFn, serversRepoFn, kms, &requestInfo)

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, nil, 1, filterFunc, repo, []string{"scopeId"})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, []byte("some hash"), 0, filterFunc, repo, []string{"scopeId"})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, []byte("some hash"), -1, filterFunc, repo, []string{"scopeId"})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := iam.ListUsers(ctx, []byte("some hash"), 1, nil, repo, []string{"scopeId"})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, nil, []string{"scopeId"})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("nil scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})

	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.User, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, nil, 1, filterFunc, tok, repo, []string{"scopeId"})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.User, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{"scopeId"})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.User, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{"scopeId"})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.User, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, []string{"scopeId"})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{"scopeId"})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.User, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{"scopeId"})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("nil scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.User, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
			return true, nil
		}
		resp, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp.Items[0],
				users[0],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		resp2, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp2.Items[0],
				users[1],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		resp3, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp3.Items[0],
				users[2],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		resp4, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp4.Items[0],
				users[3],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		resp5, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp5.Items[0],
				users[4],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		resp6, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp6.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
			return r.GetPublicId() == users[len(users)-1].GetPublicId(), nil
		}
		resp, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 1)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp.Items[0],
				users[4],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		resp2, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		// Note: this might be surprising, but there isn't any way for the refresh
		// call to know that the last call got a different number.
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Empty(t, resp2.Items)
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, r *iam.User) (bool, error) {
			return true, nil
		}
		deletedUserId := users[0].GetPublicId()
		_, err := repo.DeleteUser(ctx, deletedUserId)
		require.NoError(t, err)
		users = users[1:]

		// Run analyze to update host estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := iam.ListUsers(ctx, []byte("some hash"), 1, filterFunc, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp.Items[0],
				users[0],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		resp2, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp2.Items[0],
				users[1],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		deletedUserId = users[0].GetPublicId()
		_, err = repo.DeleteUser(ctx, deletedUserId)
		require.NoError(t, err)
		users = users[1:]

		// Run analyze to update host estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedUserId)
		require.Len(t, resp3.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp3.Items[0],
				users[1],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		resp4, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 3)
		require.Len(t, resp4.Items, 1)
		require.Empty(t,
			cmp.Diff(
				resp4.Items[0],
				users[2],
				cmpopts.IgnoreUnexported(iam.User{}, iamstore.User{}, timestamp.Timestamp{}, timestamppb.Timestamp{}),
			),
		)

		resp5, err := iam.ListUsersRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, repo, []string{o.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 3)
		require.Empty(t, resp5.Items)
	})
}
