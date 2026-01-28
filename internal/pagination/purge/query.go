// Copyright IBM Corp. 2020, 2025
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
