// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package clientcache

import "github.com/hashicorp/boundary/internal/clientcache/internal/daemon"

// SearchResult describes the output from a search query when using the CLI
type SearchResult struct {
	StatusCode int                 `json:"status_code"`
	Item       daemon.SearchResult `json:"item"`
}

// StatusResult describes the output from a status query when using the CLI
type StatusResult struct {
	StatusCode int                 `json:"status_code"`
	Item       daemon.StatusResult `json:"item"`
}

// ResourceStatus describes a field in daemon.StatusResult
type ResourceStatus = daemon.ResourceStatus
