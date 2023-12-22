// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ldap

const (
	estimateCountAccounts = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('auth_ldap_account'::regclass)
`
)
