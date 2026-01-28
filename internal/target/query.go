// Copyright IBM Corp. 2020, 2025
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
select sum(reltuples::bigint) as estimate from pg_class where oid in ('target_tcp'::regclass, 'target_ssh'::regclass,  'target_rdp'::regclass)
`

	listTargetsTemplate = `
with targets as (
    select public_id
      from target
     where %s -- search condition for applying permissions is constructed
  order by create_time desc, public_id desc
     limit %d
),
tcp_targets as (
  select *
    from target_tcp
   where public_id in (select public_id from targets)
),
ssh_targets as (
  select *
    from target_ssh
   where public_id in (select public_id from targets)
),
rdp_targets as (
  select *
    from target_rdp
   where public_id in (select public_id from targets)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         null as storage_bucket_id,
         false as enable_session_recording,
         'tcp' as type
    from tcp_targets
   union
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         storage_bucket_id,
         enable_session_recording,
         'ssh' as type
    from ssh_targets
   union
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         storage_bucket_id,
         enable_session_recording,
         'rdp' as type
    from rdp_targets
)
  select *
    from final
order by create_time desc, public_id desc;
`

	listTargetsPageTemplate = `
with targets as (
    select public_id
      from target
     where (create_time, public_id) < (@last_item_create_time, @last_item_id)
       and %s -- search condition for applying permissions is constructed
  order by create_time desc, public_id desc
     limit %d
),
tcp_targets as (
  select *
    from target_tcp
   where public_id in (select public_id from targets)
),
ssh_targets as (
  select *
    from target_ssh
   where public_id in (select public_id from targets)
),
rdp_targets as (
  select *
    from target_rdp
   where public_id in (select public_id from targets)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         null as storage_bucket_id,
         false as enable_session_recording,
         'tcp' as type
    from tcp_targets
   union
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         storage_bucket_id,
         enable_session_recording,
         'ssh' as type
    from ssh_targets
   union
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         storage_bucket_id,
         enable_session_recording,
         'rdp' as type
    from rdp_targets
)
  select *
    from final
order by create_time desc, public_id desc;
`

	refreshTargetsTemplate = `
with targets as (
    select public_id
      from target
     where update_time > @updated_after_time
       and %s -- search condition for applying permissions is constructed
  order by update_time desc, public_id desc
     limit %d
),
tcp_targets as (
  select *
    from target_tcp
   where public_id in (select public_id from targets)
),
ssh_targets as (
  select *
    from target_ssh
   where public_id in (select public_id from targets)
),
rdp_targets as (
  select *
    from target_rdp
   where public_id in (select public_id from targets)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         null as storage_bucket_id,
         false as enable_session_recording,
         'tcp' as type
    from tcp_targets
   union
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         storage_bucket_id,
         enable_session_recording,
         'ssh' as type
    from ssh_targets
   union
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         storage_bucket_id,
         enable_session_recording,
         'rdp' as type
    from rdp_targets
)
  select *
    from final
order by update_time desc, public_id desc;
`

	refreshTargetsPageTemplate = `
with targets as (
    select public_id
      from target
     where update_time > @updated_after_time
       and (update_time, public_id) < (@last_item_update_time, @last_item_id)
       and %s -- search condition for applying permissions is constructed
  order by update_time desc, public_id desc
     limit %d
),
tcp_targets as (
  select *
    from target_tcp
   where public_id in (select public_id from targets)
),
ssh_targets as (
  select *
    from target_ssh
   where public_id in (select public_id from targets)
),
rdp_targets as (
  select *
    from target_rdp
   where public_id in (select public_id from targets)
),
final as (
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         null as storage_bucket_id,
         false as enable_session_recording,
         'tcp' as type
    from tcp_targets
   union
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         storage_bucket_id,
         enable_session_recording,
         'ssh' as type
    from ssh_targets
   union
  select public_id,
         project_id,
         name,
         description,
         default_port,
         session_max_seconds,
         session_connection_limit,
         version,
         create_time,
         update_time,
         worker_filter,
         egress_worker_filter,
         ingress_worker_filter,
         default_client_port,
         storage_bucket_id,
         enable_session_recording,
         'rdp' as type
    from rdp_targets
)
  select *
    from final
order by update_time desc, public_id desc;
`

	getCredentialLibraryCredentialTypeQuery = `
select credential_type
  from credential_library
 where public_id = ?
`
)
