// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package target

// HostSource is an interface that can be implemented by both a set and a
// singular host.
type HostSource interface {
	HostCatalogId() string
	Id() string
}
