// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

// Endpoint is a struct which identifies an address provided by a host and
// selected as the priority address by the specified host set.
type Endpoint struct {
	HostId  string
	SetId   string
	Address string
}
