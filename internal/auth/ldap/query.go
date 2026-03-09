// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

const (
	estimateCountAccounts = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('auth_ldap_account'::regclass)
`
	estimateCountManagedGroups = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('auth_ldap_managed_group'::regclass)
`
)
