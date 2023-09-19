// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

const (
	estimateCountCredentialLibraries = `
  select reltuples::bigint as estimate from pg_class where oid = (current_schema() || '.credential_library')::regclass
`

	estimateCountCredentialStores = `
  select reltuples::bigint as estimate from pg_class where oid = (current_schema() || '.credential_store')::regclass
`

	estimateCountCredentials = `
  select reltuples::bigint as estimate from pg_class where oid = (current_schema() || '.credential')::regclass
`
)
