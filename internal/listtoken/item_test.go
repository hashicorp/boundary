// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package listtoken_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
)

func TestItem_Validate(t *testing.T) {
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	t.Run("valid-pagination-item", func(t *testing.T) {
		tk, err := listtoken.NewPagination(
			context.Background(),
			fiveDaysAgo,
			resource.Target,
			[]byte("some hash"),
			"some id",
			fiveDaysAgo.Add(time.Hour),
		)
		require.NoError(t, err)
		item, err := tk.LastItem(context.Background())
		require.NoError(t, err)
		err = item.Validate()
		require.NoError(t, err)
	})
	t.Run("valid-refresh-item", func(t *testing.T) {
		tk, err := listtoken.NewRefresh(
			context.Background(),
			fiveDaysAgo,
			resource.Target,
			[]byte("some hash"),
			fiveDaysAgo.Add(4*time.Hour),
			fiveDaysAgo.Add(3*time.Hour),
			fiveDaysAgo.Add(2*time.Hour),
			"some id",
			fiveDaysAgo.Add(time.Hour),
		)
		require.NoError(t, err)
		item, err := tk.LastItem(context.Background())
		require.NoError(t, err)
		err = item.Validate()
		require.NoError(t, err)
	})
	t.Run("invalid-item", func(t *testing.T) {
		item := &listtoken.Item{}
		err := item.Validate()
		require.Error(t, err)
	})
}
