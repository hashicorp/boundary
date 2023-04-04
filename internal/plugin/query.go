// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

const (
	addSupportFlagQuery = "insert into %s (public_id) values (?) on conflict do nothing;"
)
