// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package purge

const (
	selectDeletionTables = `
		select get_deletion_tables()
	`

	purgeExpiredRows = `
		delete from %s where delete_time < now() - interval '30 days'
	`
)
