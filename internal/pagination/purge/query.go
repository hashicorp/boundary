// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package purge

const (
	getDeletionTablesQuery = `
select tablename
  from deletion_table;
`
	deleteQueryTemplate = `
delete from %s where delete_time < now() - interval '30 days'
`
)
