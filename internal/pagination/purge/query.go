// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package purge

const (
	getDeletionTablesQuery = `
select get_deletion_tables();
`
	deleteQueryTemplate = `
delete from %s where delete_time < now() - interval '30 days'
`
)
