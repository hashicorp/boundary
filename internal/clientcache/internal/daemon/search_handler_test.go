// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"testing"

	"github.com/hashicorp/boundary/internal/clientcache/internal/cache"
	"github.com/stretchr/testify/assert"
)

func TestParseSortBy(t *testing.T) {
	testCases := []struct {
		inputSb        string
		inputSr        cache.SearchableResource
		expectedValid  bool
		expectedSortBy cache.SortBy
	}{
		{"name", cache.Targets, true, cache.SortByName},
		{"name", cache.Sessions, false, cache.SortByDefault},
		{"created_at", cache.Targets, false, cache.SortByDefault},
		{"created_at", cache.Sessions, true, cache.SortByCreatedAt},
		{"", cache.Targets, true, cache.SortByDefault},
		{"", cache.Sessions, true, cache.SortByDefault},
		{"ljkdhnsfg", cache.Targets, false, cache.SortByDefault},
		{"xcvbxcvb", cache.Sessions, false, cache.SortByDefault},
		{"name ", cache.Targets, false, cache.SortByDefault},      // Unicode no break space
		{"name\u202e", cache.Targets, false, cache.SortByDefault}, // Unicode RtL override
		{"\u202ename", cache.Targets, false, cache.SortByDefault}, // Unicode RtL override
	}
	for _, tc := range testCases {
		actualSortBy, actualValid := parseSortBy(tc.inputSb, tc.inputSr)
		assert.Equal(t, tc.expectedSortBy, actualSortBy)
		assert.Equal(t, tc.expectedValid, actualValid)
	}
}

func TestParseSortDirection(t *testing.T) {
	testCases := []struct {
		inputSd               string
		expectedValid         bool
		expectedSortDirection cache.SortDirection
	}{
		{"asc", true, cache.Ascending},
		{"ascending", true, cache.Ascending},
		{"desc", true, cache.Descending},
		{"descending", true, cache.Descending},
		{"", true, cache.SortDirectionDefault},
		{"asdasd", false, cache.SortDirectionDefault},
		{"asc ", false, cache.SortDirectionDefault},
		{"name\u202e", false, cache.SortDirectionDefault},
		{"\u202ename", false, cache.SortDirectionDefault},
	}
	for _, tc := range testCases {
		actualSortDirection, actualValid := parseSortDirection(tc.inputSd)
		assert.Equal(t, tc.expectedSortDirection, actualSortDirection)
		assert.Equal(t, tc.expectedValid, actualValid)
	}
}
