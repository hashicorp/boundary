// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ldap

const (
	estimateCountAccounts = `
select reltuples::bigint as estimate from pg_class where oid = (current_schema() || '.auth_account')::regclass
`
)
