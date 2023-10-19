// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package static

const (
	setChangesQuery = `
with
final_hosts (host_id) as (
  -- returns the SET list
  select public_id
    from static_host
   where public_id in (%s)
),
current_hosts (host_id) as (
  -- returns the current list
  select host_id
    from static_host_set_member
   where set_id = @1 -- this trailing space is needed by gorm
),
keep_hosts (host_id) as (
  -- returns the KEEP list
  select host_id
    from current_hosts
   where host_id in (select * from final_hosts)
),
delete_hosts (host_id) as (
  -- returns the DELETE list
  select host_id
    from current_hosts
   where host_id not in (select * from final_hosts)
),
insert_hosts (host_id) as (
  -- returns the ADD list
  select host_id
    from final_hosts
   where host_id not in (select * from keep_hosts)
),
final (action, host_id) as (
  select 'delete', host_id
    from delete_hosts
   union
  select 'add', host_id
    from insert_hosts
)
select * from final
order by action, host_id;
`

	estimateCountHosts = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('static_host'::regclass)
`
)
