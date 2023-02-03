// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

type RootInfo struct {
	// the ID for this node. For workers, this is workerId
	RootId string
	// the version of boundary the root is running
	RootVer string
}
