// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testType2 struct {
	boundary.Resource
	ID string
}

func (t *testType2) GetResourceType() resource.Type {
	return resource.Unknown
}

func (t *testType2) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.Now()
}

func (t *testType2) GetPublicId() string {
	return t.ID
}

func Test_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("no-rows", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return nil, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 0)
		// No response token expected when there were no results
		assert.Nil(t, resp.RefreshToken)
	})
	t.Run("fill-on-first-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "2"}}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "2")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("fill-on-first-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return []*testType2{{nil, "1"}, {nil, "2"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "2"}}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 2)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "2")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType2{{nil, "4"}, {nil, "5"}, {nil, "6"}}, nil
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID == "2" || item.ID == "4" || item.ID == "6" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "3"}}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "3")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("fill-on-subsequent-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType2{{nil, "4"}, {nil, "5"}}, nil
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID == "2" || item.ID == "4" || item.ID == "6" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "3"}}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "3")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType2{{nil, "4"}}, nil
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID == "2" || item.ID == "4" || item.ID == "6" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "3"}}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 2)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "3")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("dont-fill-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType2{{nil, "4"}}, nil
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID != "1" {
				// Filter every item except the first
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 1)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "1")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			switch {
			case prevPageLast == nil:
				return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
			case prevPageLast.ID == "3":
				return []*testType2{{nil, "4"}, {nil, "5"}, {nil, "6"}}, nil
			case prevPageLast.ID == "6":
				return nil, nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID != "1" {
				// Filter every item except the first
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 1)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "1")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			switch {
			case prevPageLast == nil:
				return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
			case prevPageLast.ID == "3":
				return []*testType2{{nil, "4"}, {nil, "5"}, {nil, "6"}}, nil
			case prevPageLast.ID == "6":
				return nil, nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			// Filter every item
			return false, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 0)
		assert.Nil(t, resp.RefreshToken)
	})
	t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			return nil, errors.New("failed to list")
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.ErrorContains(t, err, "failed to list")
		assert.Empty(t, resp)
	})
	t.Run("errors-when-list-errors-subsequently", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				return nil, errors.New("failed to list")
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID != "1" {
				// Filter every item except the first
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.ErrorContains(t, err, "failed to list")
		assert.Empty(t, resp)
	})
	t.Run("errors-when-filter-errors", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return false, errors.New("failed to filter")
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.ErrorContains(t, err, "failed to filter")
		assert.Empty(t, resp)
	})
	t.Run("errors-when-estimated-count-errors", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 0, errors.New("failed to estimate count")
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.ErrorContains(t, err, "failed to estimate count")
		assert.Empty(t, resp)
	})
}

func Test_ListRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("no-rows", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return nil, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "1")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("fill-on-first-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "2"}}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "2")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("fill-on-first-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return []*testType2{{nil, "1"}, {nil, "2"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "2"}}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "2")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType2{{nil, "4"}, {nil, "5"}, {nil, "6"}}, nil
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID == "2" || item.ID == "4" || item.ID == "6" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "3"}}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "3")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("fill-on-subsequent-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType2{{nil, "4"}, {nil, "5"}}, nil
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID == "2" || item.ID == "4" || item.ID == "6" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "3"}}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "3")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType2{{nil, "4"}}, nil
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID == "2" || item.ID == "4" || item.ID == "6" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}, {nil, "3"}}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "3")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("dont-fill-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType2{{nil, "4"}}, nil
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID != "1" {
				// Filter every item except the first
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "1")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			switch {
			case prevPageLast == nil:
				return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
			case prevPageLast.ID == "3":
				return []*testType2{{nil, "4"}, {nil, "5"}, {nil, "6"}}, nil
			case prevPageLast.ID == "6":
				return nil, nil
			default:
				t.Fatalf("unexpected call to listRefreshItemsFn with %#v", prevPageLast)
				return nil, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID != "1" {
				// Filter every item except the first
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType2{{nil, "1"}}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "1")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			switch {
			case prevPageLast == nil:
				return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
			case prevPageLast.ID == "3":
				return []*testType2{{nil, "4"}, {nil, "5"}, {nil, "6"}}, nil
			case prevPageLast.ID == "6":
				return nil, nil
			default:
				t.Fatalf("unexpected call to listRefreshItemsFn with %#v", prevPageLast)
				return nil, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			// Filter every item
			return false, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.RefreshToken)
		// Times should be within ~10 seconds of now
		assert.True(t, resp.RefreshToken.CreatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.CreatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Before(time.Now().Add(10*time.Second)))
		assert.True(t, resp.RefreshToken.UpdatedTime.Equal(resp.RefreshToken.CreatedTime))
		assert.Equal(t, resp.RefreshToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.RefreshToken.LastItemId, "1")
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.After(time.Now().Add(-10*time.Second)))
		assert.True(t, resp.RefreshToken.LastItemUpdatedTime.Before(time.Now().Add(10*time.Second)))
	})
	t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			return nil, errors.New("failed to list")
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.ErrorContains(t, err, "failed to list")
		assert.Empty(t, resp)
	})
	t.Run("errors-when-list-errors-subsequently", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			if prevPageLast != nil {
				return nil, errors.New("failed to list")
			}
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			if item.ID != "1" {
				// Filter every item except the first
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.ErrorContains(t, err, "failed to list")
		assert.Empty(t, resp)
	})
	t.Run("errors-when-filter-errors", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return false, errors.New("failed to filter")
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.ErrorContains(t, err, "failed to filter")
		assert.Empty(t, resp)
	})
	t.Run("errors-when-estimated-count-errors", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 0, errors.New("failed to estimate count")
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.ErrorContains(t, err, "failed to estimate count")
		assert.Empty(t, resp)
	})
	t.Run("errors-when-listing-deleted-ids-errors", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		refreshToken, err := refreshtoken.New(
			ctx,
			time.Now(),
			time.Now(),
			resource.Unknown,
			[]byte("some hash"),
			"1",
			time.Now(),
		)
		require.NoError(t, err)
		listRefreshItemsFn := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *testType2, limit int) ([]*testType2, error) {
			assert.Nil(t, prevPageLast)
			return []*testType2{{nil, "1"}, {nil, "2"}, {nil, "3"}}, nil
		}
		filterItemFn := func(ctx context.Context, item *testType2) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, time.Time{}, errors.New("failed to list deleted ids")
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(
			ctx,
			grantsHash,
			pageSize,
			filterItemFn,
			listRefreshItemsFn,
			estimatedItemCountFn,
			deletedIDsFn,
			refreshToken,
		)
		require.ErrorContains(t, err, "failed to list deleted ids")
		assert.Empty(t, resp)
	})
}
