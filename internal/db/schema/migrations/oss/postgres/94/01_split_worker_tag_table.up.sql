-- Copyright IBM Corp. 2020, 2025
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

-- Removes view created in 86/01_server_worker_local_storage_state.up.sql
-- This view is removed in favor of custom sql in query.go
drop view server_worker_aggregate;

-- Drop the old tables
drop table server_worker_tag;
drop table server_worker_tag_enm;

-- Create an index on server_worker for the new queries
create index server_worker_operational_state_type_last_status_time_idx on server_worker (operational_state, type, last_status_time);

commit;