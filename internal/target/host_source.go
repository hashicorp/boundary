// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

// HostSource is an interface that can be implemented by both a set and a
// singular host.
type HostSource interface {
	HostCatalogId() string
	Id() string
}
