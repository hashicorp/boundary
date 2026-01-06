// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

type RootInfo struct {
	// the ID for this node. For workers, this is workerId
	RootId string
	// the version of boundary the root is running
	RootVer string
}
