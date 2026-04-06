// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package authtoken

const (
	estimateCountAuthTokens = `
select reltuples::bigint as estimate from pg_class where oid in ('auth_token'::regclass)
`
)
