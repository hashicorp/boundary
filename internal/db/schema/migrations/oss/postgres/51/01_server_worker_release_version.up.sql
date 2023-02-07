-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

-- release_version can be null, but if provided it must be greater than 8 to account for
-- the 'Boundary' suffix
alter table server_worker
  add column release_version text
    constraint release_version_too_short
      check (release_version = '' or length(trim(release_version)) >= 8);

drop view server_worker_aggregate;

-- Updated in 52/01_worker_operational_state.up.sql
create view server_worker_aggregate as
with worker_config_tags(worker_id, source, tags) as (
  select
    ct.worker_id,
    ct.source,
    -- keys and tags can be any lowercase printable character so use uppercase characters as delimitors.
    string_agg(distinct concat_ws('Y', ct.key, ct.value), 'Z') as tags
  from server_worker_tag ct
  group by ct.worker_id, ct.source
),
 connection_count (worker_id, count) as (
   select
     worker_id,
     count(1) as count
   from session_connection
   where closed_reason is null
   group by worker_id
 )
select
  w.public_id,
  w.scope_id,
  w.description,
  w.name,
  w.address,
  w.create_time,
  w.update_time,
  w.version,
  w.last_status_time,
  w.type,
  w.release_version,
  cc.count as active_connection_count,
  -- keys and tags can be any lowercase printable character so use uppercase characters as delimitors.
  wt.tags as api_tags,
  ct.tags as worker_config_tags
from server_worker w
       left join worker_config_tags wt on
      w.public_id = wt.worker_id and wt.source = 'api'
       left join worker_config_tags ct on
      w.public_id = ct.worker_id and ct.source = 'configuration'
       left join connection_count as cc on
    w.public_id = cc.worker_id;
comment on view server_worker_aggregate is
  'server_worker_aggregate contains the worker resource with its worker provided config values and its configuration and api provided tags.';

commit;