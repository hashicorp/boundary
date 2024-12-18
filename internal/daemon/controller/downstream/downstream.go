// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package downstream

// Downstreamers provides at least a minimum interface that must be met by a
// Controller.downstreamWorkers field which is far better than allowing any (empty
// interface)
type Downstreamers interface {
	// RootId returns the root ID of the downstreamers' graph
	RootId() string
}
