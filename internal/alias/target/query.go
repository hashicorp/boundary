// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

const (
	estimateCount = `
select greatest(0, coalesce(sum(reltuples::bigint), 0)) as estimate from pg_class where oid in ('alias'::regclass)
`
)
