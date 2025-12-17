// Copyright IBM Corp. 2020, 2025
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
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// Some unique timestamps for tests
	timeNow              = time.Now()
	fiveDaysAgo          = timeNow.AddDate(0, 0, -5)
	tokenCreateTime      = timeNow.AddDate(0, 0, -10)
	prevDeletedTime      = fiveDaysAgo.Add(time.Hour)
	lastItemCreateTime   = fiveDaysAgo.Add(2 * time.Hour)
	lastItemUpdateTime   = fiveDaysAgo.Add(3 * time.Hour)
	listReturnTime       = timeNow.Add(-time.Second)
	deletedIDsReturnTime = timeNow.Add(-2 * time.Second)
	prevPhaseUpperBound  = fiveDaysAgo.Add(2 * time.Second)
	phaseLowerBound      = fiveDaysAgo.Add(3 * time.Second)
	phaseUpperBound      = fiveDaysAgo.Add(4 * time.Second)
)

type testType struct {
	boundary.Resource
	ID         string
	CreateTime time.Time
	UpdateTime time.Time
}

func (t *testType) GetResourceType() resource.Type {
	return resource.Target
}

func (t *testType) GetCreateTime() *timestamp.Timestamp {
	return timestamp.New(t.CreateTime)
}

func (t *testType) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(t.UpdateTime)
}

func (t *testType) GetPublicId() string {
	return t.ID
}

func Test_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("empty grants hash", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte(nil)
			_, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			pageSize := 0
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			pageSize := -1
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter item callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := ListFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil list items callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := ListItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing list items callback")
		})
		t.Run("nil estimated count callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := EstimatedCountFunc(nil)
			grantsHash := []byte("some hash")
			_, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing estimated count callback")
		})
	})
	t.Run("error-cases", func(t *testing.T) {
		t.Parallel()
		t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				if prevPageLast != nil {
					return nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
	})
	t.Run("no-rows", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
		assert.Nil(t, resp.ListToken)
	})
	t.Run("fill-on-first-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
			{nil, "2", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(listReturnTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemId, "2")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemCreateTime.Equal(lastItemCreateTime))
	})
	t.Run("fill-on-first-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
			{nil, "2", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 2)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(listReturnTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(listReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(listReturnTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemId, "3")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemCreateTime.Equal(lastItemCreateTime))
	})
	t.Run("fill-on-subsequent-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			if item.ID == "2" || item.ID == "4" {
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
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(listReturnTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemId, "3")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemCreateTime.Equal(lastItemCreateTime))
	})
	t.Run("fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			if item.ID == "2" || item.ID == "4" {
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
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 2)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(listReturnTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(listReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("dont-fill-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 1)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(listReturnTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(listReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 1)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(listReturnTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(listReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
		assert.Nil(t, resp.ListToken)
	})
}

func Test_ListPage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("empty grants hash", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte(nil)
			_, err = ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			pageSize := 0
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			pageSize := -1
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter item callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := ListFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil list items callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := ListItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "missing list items callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, nil)
			require.ErrorContains(t, err, "missing list token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil estimated count callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := EstimatedCountFunc(nil)
			grantsHash := []byte("some hash")
			_, err = ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "missing estimated count callback")
		})
	})
	t.Run("error-cases", func(t *testing.T) {
		t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-list-errors-subsequently", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				if prevPageLast != nil {
					return nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-filter-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-estimated-count-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			grantsHash := []byte("some hash")
			resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
		})
	})
	t.Run("no-rows", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewPagination(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"some id",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(tokenCreateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(tokenCreateTime))
	})
	t.Run("fill-on-first-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewPagination(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"some id",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
			{nil, "2", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemId, "2")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemCreateTime.Equal(lastItemCreateTime))
	})
	t.Run("fill-on-first-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewPagination(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"some id",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
			{nil, "2", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(tokenCreateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(tokenCreateTime))
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewPagination(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"some id",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
		resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemId, "3")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemCreateTime.Equal(lastItemCreateTime))
	})
	t.Run("fill-on-subsequent-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewPagination(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"some id",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			if item.ID == "2" || item.ID == "4" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemId, "3")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.PaginationToken).LastItemCreateTime.Equal(lastItemCreateTime))
	})
	t.Run("fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewPagination(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"some id",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			if item.ID == "2" || item.ID == "4" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(tokenCreateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(tokenCreateTime))
	})
	t.Run("dont-fill-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewPagination(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"some id",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
		resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(tokenCreateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(tokenCreateTime))
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewPagination(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"some id",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
		resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(tokenCreateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(tokenCreateTime))
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewPagination(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			"some id",
			lastItemCreateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			// Filter every item
			return false, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(tokenCreateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(tokenCreateTime))
	})
}

func Test_ListRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("empty grants hash", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte(nil)
			_, err = ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			pageSize := 0
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			pageSize := -1
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter item callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := ListFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil list items callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := ListItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing list items callback")
		})
		t.Run("nil list deleted ids callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := ListDeletedIDsFunc(nil)
			grantsHash := []byte("some hash")
			_, err = ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing list deleted IDs callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, nil)
			require.ErrorContains(t, err, "missing list token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "token did not have a start-refresh token component")
		})
		t.Run("nil estimated count callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := EstimatedCountFunc(nil)
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing estimated count callback")
		})
	})
	t.Run("error-cases", func(t *testing.T) {
		t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-list-errors-subsequently", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				if prevPageLast != nil {
					return nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-filter-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-estimated-count-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-list-deleted-ids-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewStartRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				prevPhaseUpperBound,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list deleted IDs")
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list deleted IDs")
			assert.Empty(t, resp)
		})
	})
	t.Run("no-rows", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewStartRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			prevPhaseUpperBound,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("fill-on-first-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewStartRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			prevPhaseUpperBound,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
			{nil, "2", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemId, "2")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemUpdateTime.Equal(lastItemUpdateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseLowerBound.Equal(prevPhaseUpperBound))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("fill-on-first-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewStartRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			prevPhaseUpperBound,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
			{nil, "2", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewStartRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			prevPhaseUpperBound,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemId, "3")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemUpdateTime.Equal(lastItemUpdateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseLowerBound.Equal(prevPhaseUpperBound))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("fill-on-subsequent-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewStartRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			prevPhaseUpperBound,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			if item.ID == "2" || item.ID == "4" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemId, "3")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemUpdateTime.Equal(lastItemUpdateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseLowerBound.Equal(prevPhaseUpperBound))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewStartRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			prevPhaseUpperBound,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			if item.ID == "2" || item.ID == "4" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("dont-fill-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewStartRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			prevPhaseUpperBound,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewStartRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			prevPhaseUpperBound,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewStartRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			prevPhaseUpperBound,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			// Filter every item
			return false, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(listReturnTime))
	})
}

func Test_ListRefreshPage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("empty grants hash", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte(nil)
			_, err = ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			pageSize := 0
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			pageSize := -1
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter item callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := ListFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil list items callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := ListItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing list items callback")
		})
		t.Run("nil list deleted ids callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := ListDeletedIDsFunc(nil)
			grantsHash := []byte("some hash")
			_, err = ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing list deleted IDs callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, nil)
			require.ErrorContains(t, err, "missing list token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewPagination(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				"some id",
				lastItemCreateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil estimated count callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := EstimatedCountFunc(nil)
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, err = ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing estimated count callback")
		})
	})
	t.Run("error-cases", func(t *testing.T) {
		t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-list-errors-subsequently", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				if prevPageLast != nil {
					return nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-filter-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-estimated-count-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
		})
		t.Run("errors-when-list-deleted-ids-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			tok, err := listtoken.NewRefresh(
				ctx,
				tokenCreateTime,
				resource.Target,
				[]byte("some hash"),
				prevDeletedTime,
				phaseUpperBound,
				phaseLowerBound,
				"some id",
				lastItemUpdateTime,
			)
			require.NoError(t, err)
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list deleted IDs")
			}
			grantsHash := []byte("some hash")
			resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list deleted IDs")
			assert.Empty(t, resp)
		})
	})
	t.Run("no-rows", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			lastItemUpdateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(phaseUpperBound))
	})
	t.Run("fill-on-first-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			lastItemUpdateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
			{nil, "2", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemId, "2")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemUpdateTime.Equal(lastItemUpdateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseLowerBound.Equal(phaseLowerBound))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseUpperBound.Equal(phaseUpperBound))
	})
	t.Run("fill-on-first-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			lastItemUpdateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
			{nil, "2", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(phaseUpperBound))
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			lastItemUpdateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemId, "3")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemUpdateTime.Equal(lastItemUpdateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseLowerBound.Equal(phaseLowerBound))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseUpperBound.Equal(phaseUpperBound))
	})
	t.Run("fill-on-subsequent-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			lastItemUpdateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			if item.ID == "2" || item.ID == "4" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.False(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.Equal(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemId, "3")
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).LastItemUpdateTime.Equal(lastItemUpdateTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseLowerBound.Equal(phaseLowerBound))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.RefreshToken).PhaseUpperBound.Equal(phaseUpperBound))
	})
	t.Run("fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			lastItemUpdateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			if item.ID == "2" || item.ID == "4" {
				// Filter every other item
				return false, nil
			}
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
			{nil, "3", lastItemCreateTime, lastItemUpdateTime},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(phaseUpperBound))
	})
	t.Run("dont-fill-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			lastItemUpdateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(phaseUpperBound))
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			lastItemUpdateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
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
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(resp.Items, []*testType{
			{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
		}))
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(phaseUpperBound))
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		tok, err := listtoken.NewRefresh(
			ctx,
			tokenCreateTime,
			resource.Target,
			[]byte("some hash"),
			prevDeletedTime,
			phaseUpperBound,
			phaseLowerBound,
			"some id",
			lastItemUpdateTime,
		)
		require.NoError(t, err)
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType) (bool, error) {
			// Filter every item
			return false, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, err := ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Equal(t, []string{"deleted-id"}, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 10)
		require.NotNil(t, resp.ListToken)
		assert.True(t, resp.ListToken.CreateTime.Equal(tokenCreateTime))
		assert.Equal(t, resp.ListToken.GrantsHash, grantsHash)
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousDeletedIdsTime.Equal(deletedIDsReturnTime))
		assert.True(t, resp.ListToken.Subtype.(*listtoken.StartRefreshToken).PreviousPhaseUpperBound.Equal(phaseUpperBound))
	})
}
