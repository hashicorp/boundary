-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table session drop constraint session_scope_id_fkey;
  alter table session rename column scope_id to project_id;

  alter table session
    add constraint iam_scope_project_fkey
      foreign key (project_id)
        references iam_scope_project (scope_id)
        on delete set null
        on update cascade
  ;

  -- Replaces trigger from 01/50_session.up.sql
  -- Replaced in 56/02_add_data_key_foreign_key_references
  create or replace function cancel_session_with_null_fk() returns trigger
  as $$
  begin
   case
      when new.user_id is null then
        perform cancel_session(new.public_id);
      when new.host_id is null then
        perform cancel_session(new.public_id);
      when new.target_id is null then
        perform cancel_session(new.public_id);
      when new.host_set_id is null then
        perform cancel_session(new.public_id);
      when new.auth_token_id is null then
        perform cancel_session(new.public_id);
      when new.project_id is null then
        perform cancel_session(new.public_id);
    end case;
    return new;
  end;
  $$ language plpgsql;

  -- Replaces trigger from 01/50_session.up.sql
  -- Replaced trigger in 60/02_sessions.up.sql
  create or replace function insert_session() returns trigger
  as $$
  begin
    case
      when new.user_id is null then
        raise exception 'user_id is null';
      when new.host_id is null then
        raise exception 'host_id is null';
      when new.target_id is null then
        raise exception 'target_id is null';
      when new.host_set_id is null then
        raise exception 'host_set_id is null';
      when new.auth_token_id is null then
        raise exception 'auth_token_id is null';
      when new.project_id is null then
        raise exception 'project_id is null';
      when new.endpoint is null then
        raise exception 'endpoint is null';
    else
    end case;
    return new;
  end;
  $$ language plpgsql;

  -- Replaces view from 34/04_views.up.sql
  -- Replaced in 56/06_add_session_private_key_column
  drop view session_list;
  create view session_list as
  select
    s.public_id, s.user_id, s.host_id, s.target_id,
    s.host_set_id, s.auth_token_id, s.project_id, s.certificate,s.expiration_time,
    s.connection_limit, s.tofu_token, s.key_id, s.termination_reason, s.version,
    s.create_time, s.update_time, s.endpoint, s.worker_filter,
    ss.state, ss.previous_end_time, ss.start_time, ss.end_time, sc.public_id as connection_id,
    sc.client_tcp_address, sc.client_tcp_port, sc.endpoint_tcp_address, sc.endpoint_tcp_port,
    sc.bytes_up, sc.bytes_down, sc.closed_reason
  from session s
    join session_state ss on
      s.public_id = ss.session_id
    left join session_connection sc on
      s.public_id = sc.session_id;

commit;
