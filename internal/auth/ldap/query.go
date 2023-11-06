// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ldap

const (
	estimateCountLdapAccounts = `
select reltuples::bigint as estimate from pg_class where oid in ('auth_ldap_account'::regclass)
`
	estimateCountLdapAuthMethods = `
select reltuples::bigint as estimate from pg_class where oid in ('auth_ldap_method'::regclass)
`
	estimateCountLdapManagedGroups = `
select reltuples::bigint as estimate from pg_class where oid in ('auth_ldap_managed_group'::regclass)
`
)
