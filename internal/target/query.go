// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

const (
	setChangesQuery = `
with
set_sources (source_id, type) as (
  -- returns the SET list
  select public_id, type
    from credential_source_all_types
   where public_id in (%s)
),
current_sources (source_id, type) as (
  -- returns the current list
  select credential_library_id, 'library'
    from target_credential_library
   where target_id          = @target_id
     and credential_purpose = @purpose
  union
  select credential_static_id, 'static'
    from target_static_credential
   where target_id          = @target_id
     and credential_purpose = @purpose
),
keep_sources (source_id) as (
  -- returns the KEEP list
  select source_id
    from current_sources
   where source_id in (select source_id from set_sources)
),
delete_sources (source_id, type) as (
  -- returns the DELETE list
  select source_id, type
    from current_sources
   where source_id not in (select source_id from set_sources)
),
insert_sources (source_id, type) as (
  -- returns the ADD list
  select source_id, type
    from set_sources
   where source_id not in (select * from keep_sources)
),
final (action, source_id, type) as (
  select 'delete', source_id, type
    from delete_sources
   union
  select 'add', source_id, type
    from insert_sources
)
select * from final
order by action, source_id;
`

	targetPublicIdList = `
select public_id, project_id from target
%s
;
`

	estimateCountTargets = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('target_tcp'::regclass, 'target_ssh'::regclass)
`
)
