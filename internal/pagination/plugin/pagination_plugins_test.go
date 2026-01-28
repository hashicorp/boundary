// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ListPlugins(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("empty grants hash", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte(nil)
			_, _, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			pageSize := 0
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			pageSize := -1
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter item callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := ListPluginsFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil list items callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := ListPluginsItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing list items callback")
		})
		t.Run("nil estimated count callback", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := pagination.EstimatedCountFunc(nil)
			grantsHash := []byte("some hash")
			_, _, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "missing estimated count callback")
		})
	})
	t.Run("error-cases", func(t *testing.T) {
		t.Parallel()
		t.Run("errors-when-list-errors-immediately", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				return nil, nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
		})
		t.Run("errors-when-list-errors-subsequently", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				if prevPageLast != nil {
					return nil, nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
			resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
		})
		t.Run("errors-when-filter-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
		})
		t.Run("errors-when-estimated-count-errors", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
		})
	})
	t.Run("no-rows", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 0)
		// No response token expected when there were no results
		assert.Nil(t, resp.ListToken)
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("fill-on-first-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("fill-on-first-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("fill-on-subsequent-with-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("fill-on-subsequent-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("fill-on-subsequent", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("dont-fill-without-remaining", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("dont-fill-with-full-last-page", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlgs, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlgs, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("filter-everything", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlgs, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlgs, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			// Filter every item
			return false, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
		require.NoError(t, err)
		assert.Empty(t, resp.Items)
		assert.True(t, resp.CompleteListing)
		assert.Empty(t, resp.DeletedIds)
		assert.Equal(t, resp.EstimatedItemCount, 0)
		assert.Nil(t, resp.ListToken)
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("appends-and-deduplicates-plugins-between-invocation", func(t *testing.T) {
		t.Parallel()
		pageSize := 2
		plg1 := plugin.NewPlugin()
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin()
		plg2.PublicId = "id2"
		plg3 := plugin.NewPlugin()
		plg3.PublicId = "id3"
		origPlgs := []*plugin.Plugin{plg1, plg2}
		otherPlgs := []*plugin.Plugin{plg2, plg3}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, otherPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn)
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
		assert.Equal(
			t,
			map[string]*plugin.Plugin{plg1.PublicId: plg1, plg2.PublicId: plg2, plg3.PublicId: plg3},
			plgs,
		)
	})
}

func Test_ListPluginsPage(t *testing.T) {
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte(nil)
			_, _, err = ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := ListPluginsFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := ListPluginsItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "missing list items callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, nil)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := pagination.EstimatedCountFunc(nil)
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				return nil, nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				if prevPageLast != nil {
					return nil, nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
			resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlgs, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlgs, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlgs, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlgs, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			// Filter every item
			return false, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("appends-and-deduplicates-plugins-between-invocation", func(t *testing.T) {
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
		plg1 := plugin.NewPlugin()
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin()
		plg2.PublicId = "id2"
		plg3 := plugin.NewPlugin()
		plg3.PublicId = "id3"
		origPlgs := []*plugin.Plugin{plg1, plg2}
		otherPlgs := []*plugin.Plugin{plg2, plg3}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, otherPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, tok)
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
		assert.Equal(
			t,
			map[string]*plugin.Plugin{plg1.PublicId: plg1, plg2.PublicId: plg2, plg3.PublicId: plg3},
			plgs,
		)
	})
}

func Test_ListPluginsRefresh(t *testing.T) {
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte(nil)
			_, _, err = ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := ListPluginsFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := ListPluginsItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := pagination.ListDeletedIDsFunc(nil)
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing list deleted IDs callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, nil)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := pagination.EstimatedCountFunc(nil)
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				return nil, nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				if prevPageLast != nil {
					return nil, nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
			resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list deleted IDs")
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list deleted IDs")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlgs, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlgs, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlgs, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlgs, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("appends-and-deduplicates-plugins-between-invocation", func(t *testing.T) {
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
		plg1 := plugin.NewPlugin()
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin()
		plg2.PublicId = "id2"
		plg3 := plugin.NewPlugin()
		plg3.PublicId = "id3"
		origPlgs := []*plugin.Plugin{plg1, plg2}
		otherPlgs := []*plugin.Plugin{plg2, plg3}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, otherPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(
			t,
			map[string]*plugin.Plugin{plg1.PublicId: plg1, plg2.PublicId: plg2, plg3.PublicId: plg3},
			plgs,
		)
	})
}

func Test_ListPluginsRefreshPage(t *testing.T) {
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte(nil)
			_, _, err = ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := ListPluginsFilterFunc[*testType](nil)
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := ListPluginsItemsFunc[*testType](nil)
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := pagination.ListDeletedIDsFunc(nil)
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "missing list deleted IDs callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			pageSize := 2
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, nil)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return nil, nil, time.Time{}, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := pagination.EstimatedCountFunc(nil)
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			_, _, err = ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				return nil, nil, time.Time{}, errors.New("failed to list")
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				if prevPageLast != nil {
					return nil, nil, time.Time{}, errors.New("failed to list")
				}
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
			resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return false, errors.New("failed to filter")
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to filter")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 0, errors.New("failed to estimate count")
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, deletedIDsReturnTime, nil
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to estimate count")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
			plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
			plg1.PublicId = "id1"
			plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
			plg2.PublicId = "id2"
			origPlgs := []*plugin.Plugin{plg1, plg2}
			listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
				assert.Nil(t, prevPageLast)
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "2", lastItemCreateTime, lastItemUpdateTime},
					{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, origPlgs, listReturnTime, nil
			}
			filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			estimatedItemCountFn := func(ctx context.Context) (int, error) {
				return 10, nil
			}
			deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
				return nil, time.Time{}, errors.New("failed to list deleted IDs")
			}
			grantsHash := []byte("some hash")
			resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
			require.ErrorContains(t, err, "failed to list deleted IDs")
			assert.Empty(t, resp)
			assert.Empty(t, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return nil, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return nil, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
				{nil, "3", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			assert.Nil(t, prevPageLast)
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "2", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		estimatedItemCountFn := func(ctx context.Context) (int, error) {
			return 10, nil
		}
		deletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
			return []string{"deleted-id"}, deletedIDsReturnTime, nil
		}
		grantsHash := []byte("some hash")
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlgs, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlgs, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
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
		plg1 := plugin.NewPlugin(plugin.WithName("plugin-1"))
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin(plugin.WithName("plugin-2"))
		plg2.PublicId = "id2"
		plgsMap := map[string]*plugin.Plugin{
			plg1.PublicId: plg1,
			plg2.PublicId: plg2,
		}
		origPlgs := []*plugin.Plugin{plg1, plg2}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			switch {
			case prevPageLast == nil:
				return []*testType{
					{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
					{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
					{nil, "3", lastItemCreateTime, lastItemUpdateTime},
				}, origPlgs, listReturnTime, nil
			case prevPageLast.ID == "3":
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
					{nil, "5", lastItemCreateTime.Add(-2 * time.Second), lastItemUpdateTime.Add(-2 * time.Second)},
					{nil, "6", lastItemCreateTime.Add(-3 * time.Second), lastItemUpdateTime.Add(-3 * time.Second)},
				}, origPlgs, listReturnTime.Add(time.Second), nil
			case prevPageLast.ID == "6":
				return nil, origPlgs, listReturnTime.Add(2 * time.Second), nil
			default:
				t.Fatalf("unexpected call to listItemsFn with %#v", prevPageLast)
				return nil, nil, time.Time{}, nil
			}
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(t, plgsMap, plgs)
	})
	t.Run("appends-and-deduplicates-plugins-between-invocation", func(t *testing.T) {
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
		plg1 := plugin.NewPlugin()
		plg1.PublicId = "id1"
		plg2 := plugin.NewPlugin()
		plg2.PublicId = "id2"
		plg3 := plugin.NewPlugin()
		plg3.PublicId = "id3"
		origPlgs := []*plugin.Plugin{plg1, plg2}
		otherPlgs := []*plugin.Plugin{plg2, plg3}
		listItemsFn := func(ctx context.Context, prevPageLast *testType, limit int) ([]*testType, []*plugin.Plugin, time.Time, error) {
			if prevPageLast != nil {
				assert.Equal(t, "3", prevPageLast.ID)
				return []*testType{
					{nil, "4", lastItemCreateTime.Add(-time.Second), lastItemUpdateTime.Add(-time.Second)},
				}, otherPlgs, listReturnTime.Add(time.Second), nil
			}
			return []*testType{
				{nil, "1", lastItemCreateTime.Add(2 * time.Second), lastItemUpdateTime.Add(2 * time.Second)},
				{nil, "2", lastItemCreateTime.Add(time.Second), lastItemUpdateTime.Add(time.Second)},
				{nil, "3", lastItemCreateTime, lastItemUpdateTime},
			}, origPlgs, listReturnTime, nil
		}
		filterItemFn := func(ctx context.Context, item *testType, plgs map[string]*plugin.Plugin) (bool, error) {
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
		resp, plgs, err := ListPluginsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedItemCountFn, deletedIDsFn, tok)
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
		assert.Equal(
			t,
			map[string]*plugin.Plugin{plg1.PublicId: plg1, plg2.PublicId: plg2, plg3.PublicId: plg3},
			plgs,
		)
	})
}
