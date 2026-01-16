// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

const (
	acctUpsertQuery = `
	insert into auth_oidc_account
			(%s)
	values
			(%s)
	on conflict on constraint 
			auth_oidc_account_auth_method_id_issuer_subject_uq
	do update set
			%s
	returning public_id, version
       `

	estimateCountAccounts = `
	select sum(reltuples::bigint) as estimate from pg_class where oid in ('auth_oidc_account'::regclass)
	`
	estimateCountManagedGroups = `
	select sum(reltuples::bigint) as estimate from pg_class where oid in ('auth_oidc_managed_group'::regclass)
	`
)
