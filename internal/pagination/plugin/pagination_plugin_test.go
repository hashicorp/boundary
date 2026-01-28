// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/plugin"
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

func Test_ListPlugin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("empty grants hash", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte(nil)
			_, _, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			pageSize := 0
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			pageSize := -1
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter item callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := ListPluginFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil list items callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := ListPluginItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing list items callback")
		})
		t.Run("nil estimated count callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := pagination.EstimatedCountFunc(nil)
			grantsHash := []byte("some hash")
			_, _, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing estimated count callback")
		})
	})
	t.Run("error-cases", func(t *testing.T) {
		t.Parallel()
		t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				return nil, nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
		})
		t.Run("errors-when-list-errors-subsequently", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				if prevPageLast != nil {
					return nil, nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
			resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
		})
		t.Run("errors-when-filter-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
		})
		t.Run("errors-when-estimated-count-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
		})
		t.Run("errors-when-plugin-changes-between-invocations", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			origPlg := plugin.NewPlugin()
			origPlg.PublicId = "id1"
			otherPlg := plugin.NewPlugin()
			otherPlg.PublicId = "id2"
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				if prevPageLast == nil {
					return []*testType{
						{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
						{nil, "2", lastItemCreateTime, lastItemUpdateTime},
						{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					}, origPlg, listReturnTime, nil
				}
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "5", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-4 * time.Second), lastItemUpdateTime.Add(-4 * time.Second)},
				}, otherPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
			resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "plugin changed between list invocations")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
		})
	})
	t.Run("no-rows", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 0)
		// No response token expected when there were no results
		assert.Nil(t, resp.ListToken)
		assert.Equal(t, origPlg, plg)
	})
	t.Run("fill-on-first-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, origPlg, plg)
	})
	t.Run("fill-on-first-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, origPlg, plg)
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, origPlg, plg)
	})
	t.Run("fill-on-subsequent-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, origPlg, plg)
	})
	t.Run("fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, origPlg, plg)
	})
	t.Run("dont-fill-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, origPlg, plg)
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlg, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlg, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, origPlg, plg)
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlg, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlg, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			// Filter every item
			return false, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPlugin(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 0)
		assert.Nil(t, resp.ListToken)
		assert.Equal(t, origPlg, plg)
	})
}

func Test_ListPluginPage(t *testing.T) {
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte(nil)
			_, _, err = ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := ListPluginFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := ListPluginItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "missing list items callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, nil)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := pagination.EstimatedCountFunc(nil)
			grantsHash := []byte("some hash")
			_, _, err = ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				return nil, nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				if prevPageLast != nil {
					return nil, nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
			resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
		})
		t.Run("errors-when-plugin-changes-between-invocations", func(t *testing.T) {
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
			origPlg := plugin.NewPlugin()
			origPlg.PublicId = "id1"
			otherPlg := plugin.NewPlugin()
			otherPlg.PublicId = "id2"
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				if prevPageLast == nil {
					return []*testType{
						{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
						{nil, "2", lastItemCreateTime, lastItemUpdateTime},
						{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					}, origPlg, listReturnTime, nil
				}
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "5", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-4 * time.Second), lastItemUpdateTime.Add(-4 * time.Second)},
				}, otherPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
			resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "plugin changed between list invocations")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlg, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlg, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlg, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlg, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			// Filter every item
			return false, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, origPlg, plg)
	})
}

func Test_ListPluginRefresh(t *testing.T) {
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte(nil)
			_, _, err = ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := ListPluginFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := ListPluginItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := pagination.ListDeletedIDsFunc(nil)
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing list deleted IDs callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, nil)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := pagination.EstimatedCountFunc(nil)
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				return nil, nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				if prevPageLast != nil {
					return nil, nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
			resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list deleted IDs")
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list deleted IDs")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
		})
		t.Run("errors-when-plugin-changes-between-invocations", func(t *testing.T) {
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
			origPlg := plugin.NewPlugin()
			origPlg.PublicId = "id1"
			otherPlg := plugin.NewPlugin()
			otherPlg.PublicId = "id2"
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				if prevPageLast == nil {
					return []*testType{
						{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
						{nil, "2", lastItemCreateTime, lastItemUpdateTime},
						{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					}, origPlg, listReturnTime, nil
				}
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "5", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-4 * time.Second), lastItemUpdateTime.Add(-4 * time.Second)},
				}, otherPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "plugin changed between list invocations")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlg, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlg, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlg, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlg, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
	})
}

func Test_ListPluginRefreshPage(t *testing.T) {
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte(nil)
			_, _, err = ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := ListPluginFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := ListPluginItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := pagination.ListDeletedIDsFunc(nil)
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing list deleted IDs callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, nil)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := pagination.EstimatedCountFunc(nil)
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				return nil, nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				if prevPageLast != nil {
					return nil, nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
			resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
			origPlg := plugin.NewPlugin()
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list deleted IDs")
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list deleted IDs")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
		})
		t.Run("errors-when-plugin-changes-between-invocations", func(t *testing.T) {
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
			origPlg := plugin.NewPlugin()
			origPlg.PublicId = "id1"
			otherPlg := plugin.NewPlugin()
			otherPlg.PublicId = "id2"
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
				if prevPageLast == nil {
					return []*testType{
						{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
						{nil, "2", lastItemCreateTime, lastItemUpdateTime},
						{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					}, origPlg, listReturnTime, nil
				}
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "5", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-4 * time.Second), lastItemUpdateTime.Add(-4 * time.Second)},
				}, otherPlg, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "plugin changed between list invocations")
			assert.Empty(t, resp)
			assert.Empty(t, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlg, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlg, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlg, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
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
		origPlg := plugin.NewPlugin()
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, *plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlg, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlg, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlg, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plg *plugin.Plugin) (bool, error) {
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
		resp, plg, err := ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, origPlg, plg)
	})
}
