-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table target_ssh_hst (
    public_id wt_public_id not null,
    project_id wt_scope_id not null,
    name text not null,
    description text null,
    default_port integer null,
    session_max_seconds integer not null,
    session_connection_limit integer not null,
    worker_filter wt_bexprfilter null,
    egress_worker_filter wt_bexprfilter null,
    ingress_worker_filter wt_bexprfilter null,
    default_client_port integer null,
    enable_session_recording boolean not null,
    storage_bucket_id wt_public_id null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint target_ssh_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table target_ssh_hst is
    'target_ssh_hst is a history table where each row contains the values from a row '
    'in the target_ssh table during the time range in the valid_range column.';

  create trigger hst_on_insert after insert on target_ssh
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on target_ssh
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on target_ssh
    for each row execute function hst_on_delete();

  insert into target_ssh_hst (
         public_id,
         project_id,          name,                     description,
         default_port,        session_max_seconds,      session_connection_limit,
         worker_filter,       egress_worker_filter,     ingress_worker_filter,
         default_client_port, enable_session_recording, storage_bucket_id
  )
  select public_id,
         project_id,          name,                     description,
         default_port,        session_max_seconds,      session_connection_limit,
         worker_filter,       egress_worker_filter,     ingress_worker_filter,
         default_client_port, enable_session_recording, storage_bucket_id
    from target_ssh;

commit;
