// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ldap

const (
	estimateCountAccounts = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('auth_ldap_account'::regclass)
`
	accurateCountAccounts = `
	select count(*) from auth_ldap_account
`
	estimateCountManagedGroups = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('auth_ldap_managed_group'::regclass)
`
	accurateCountManagedGroups = `
	select count(*) from auth_ldap_managed_group
`
)
