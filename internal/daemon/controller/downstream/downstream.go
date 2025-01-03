// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package downstream

// Graph provides at least a minimum interface that must be met by a
// Controller.downstreamWorkers field which is far better than allowing any (empty
// interface)
// This is used to interact with downstream workers DAG
type Graph interface {
	// RootId returns the root ID of the graph
	RootId() string
}
