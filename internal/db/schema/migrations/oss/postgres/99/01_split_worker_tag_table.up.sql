-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Create new tables for worker config and worker api tags
create table server_worker_config_tag(
  worker_id wt_public_id
    constraint server_worker_fkey
      references server_worker (public_id)
      on delete cascade
      on update cascade,
  key wt_tagpair,
  value wt_tagpair,
  primary key (worker_id, key, value)
);
comment on table server_worker_config_tag is
  'server_worker_config_tag is a table where each row represents a worker config tag.';

create table server_worker_api_tag(
  worker_id wt_public_id
    constraint server_worker_fkey
      references server_worker (public_id)
      on delete cascade
      on update cascade,
  key wt_tagpair,
  value wt_tagpair,
  primary key (worker_id, key, value)
);
comment on table server_worker_api_tag is
  'server_worker_api_tag is a table where each row represents a worker api tag.';

-- Migrate from server_worker_tag to the new tables
 insert into server_worker_config_tag
             (worker_id, key, value)
      select worker_id, key, value
        from server_worker_tag
       where source = 'configuration';

 insert into server_worker_api_tag
             (worker_id, key, value)
      select worker_id, key, value
        from server_worker_tag
       where source = 'api';


drop view server_worker_aggregate;
-- Replaces view created in 86/01_server_worker_local_storage_state.up.sql to use the disparate worker tag tables
-- View also switches to using json_agg to build the tags for consumption
-- TODO this view will be completely dropped in future PRs on this LLB in favor of sql in query.go
create view server_worker_aggregate as
  with connection_count (worker_id, count) as (
    select worker_id,
           count(1) as count
      from session_connection
      where closed_reason is null
   group by worker_id
)
    select w.public_id,
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
           w.operational_state,
           w.local_storage_state,
           cc.count as active_connection_count,
           wt.tags as api_tags,
           ct.tags as worker_config_tags
      from server_worker w
 left join (select worker_id, json_agg(json_build_object('key', key, 'value', value)) as tags from server_worker_api_tag group by worker_id) wt
        on w.public_id = wt.worker_id
 left join (select worker_id, json_agg(json_build_object('key', key, 'value', value)) as tags from server_worker_config_tag group by worker_id) ct
        on w.public_id = ct.worker_id
 left join connection_count as cc
        on w.public_id = cc.worker_id;
comment on view server_worker_aggregate is
  'server_worker_aggregate contains the worker resource with its worker provided config values and its configuration and api provided tags.';

-- Drop the old tables
drop table server_worker_tag;
drop table server_worker_tag_enm;

commit;