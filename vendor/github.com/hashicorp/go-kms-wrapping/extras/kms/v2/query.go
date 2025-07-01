// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

const (
	postgresForeignReferencersQuery = `
select distinct
	r.table_name
from
	information_schema.constraint_column_usage            u
	inner join information_schema.referential_constraints fk
		on u.constraint_catalog = fk.unique_constraint_catalog
			and u.constraint_schema = fk.unique_constraint_schema
			and u.constraint_name = fk.unique_constraint_name
	inner join information_schema.key_column_usage        r
		on r.constraint_catalog = fk.constraint_catalog
			and r.constraint_schema = fk.constraint_schema
			and r.constraint_name = fk.constraint_name
where
	u.column_name = 'private_id' and
	u.table_name = 'kms_data_key_version'
`
	sqliteForeignReferencersQuery = `
select 
	m.name
from
	sqlite_master m
	join pragma_foreign_key_list(m.name) p on m.name != p."table"
where 
	m.type = 'table' and
	p."table" = 'kms_data_key_version' and
	p."to" = 'private_id'
`
)
