-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Update tables. Value can be null in all cases.
alter table target_tcp
  add column default_client_port int;
alter table target_ssh
  add column default_client_port int;

-- Update views
-- Replaces target_all_subtypes defined in 64/01_ssh_targets.up.sql
create or replace view target_all_subtypes as
select
  public_id,
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
  'tcp' as type,
  default_client_port
from target_tcp
union
select
  public_id,
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
  'ssh' as type,
  default_client_port
from
  target_ssh;

commit;
