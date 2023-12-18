// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package clientcache

import "github.com/hashicorp/boundary/internal/clientcache/internal/daemon"

type SearchResult struct {
	StatusCode int                 `json:"status_code"`
	Item       daemon.SearchResult `json:"item"`
}

type StatusResult struct {
	StatusCode int                 `json:"status_code"`
	Item       daemon.StatusResult `json:"item"`
}
