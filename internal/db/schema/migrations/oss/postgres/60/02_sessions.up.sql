-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Replaces trigger from 56/02_add_data_key_foreign_key_references.up.sql
  drop trigger cancel_session_with_null_fk on session;
  create or replace function cancel_session_with_null_fk() returns trigger
  as $$
  begin
    -- Note that we need each of these to run in case
    -- more than one of them is null.
    if new.auth_token_id is null then
      perform cancel_session(new.public_id);
    end if;
    if new.project_id is null then
      -- Setting the key_id to null will allow the scope
      -- to cascade delete its keys.
      new.key_id = null;
      perform cancel_session(new.public_id);
    end if;
    if new.target_id is null then
      perform cancel_session(new.public_id);
    end if;
    if new.user_id is null then
      perform cancel_session(new.public_id);
    end if;
    return new;
  end;
  $$ language plpgsql;
  
  create trigger cancel_session_with_null_fk before update of auth_token_id, project_id, target_id, user_id on session
    for each row execute procedure cancel_session_with_null_fk();

  create table session_target_address (
    session_id wt_public_id primary key,
    target_id wt_public_id,
    -- the following foreign key constraint is set to null on a delete
    -- because we want to be able to invoke a trigger to call cancel_session
    -- when the references column is deleted
    -- rather than canceling a session for any reason that may cause a row to be deleted.
    constraint target_address_fkey foreign key (target_id)
        references target_address (target_id)
        on delete set null
        on update cascade,
    constraint session_fkey foreign key (session_id)
        references session (public_id)
        on delete cascade
        on update cascade,
    constraint session_target_address_session_id_target_id_uq
        unique(session_id, target_id)
  );
  comment on table session_target_address is
    'session_target_address entries represent a session that is using a network address that is assigned directly to a Target.';

  create trigger immutable_columns before update on session_target_address
    for each row execute procedure immutable_columns('session_id');

  create function cancel_session_with_null_target_address_fk() returns trigger
  as $$
  begin
    if new.target_id is null then
      perform cancel_session(new.session_id);
      delete from session_target_address where session_id = new.session_id;
    end if;
    return new;
  end;
  $$ language plpgsql;
  
  create trigger cancel_session_with_null_target_address_fk after update of target_id on session_target_address
    for each row execute procedure cancel_session_with_null_target_address_fk();

  create function insert_session_target_address() returns trigger
  as $$
  begin
    if new.target_id is null then
      raise exception 'target_id is null';
    end if;
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_session_target_address before insert on session_target_address
    for each row execute procedure insert_session_target_address();

  create table session_host_set_host (
    session_id wt_public_id primary key,
    host_set_id wt_public_id,
    host_id wt_public_id,
    -- the following foreign key constraints for host_set_id & host_id is set to null on a delete
    -- because we want to be able to invoke a trigger to call cancel_session
    -- when the references column is deleted
    -- rather than canceling a session for any reason that may cause a row to be deleted.
    constraint host_set_fkey foreign key (host_set_id)
        references host_set (public_id)
        on delete set null
        on update cascade,
    constraint host_fkey foreign key (host_id)
        references host (public_id)
        on delete set null
        on update cascade,
    constraint session_fkey foreign key (session_id)
        references session (public_id)
        on delete cascade
        on update cascade,
    constraint session_host_set_host_session_id_host_set_id_host_id_uq
        unique(session_id, host_set_id, host_id)
  );
  comment on table session_host_set_host is
    'session_host_set entries represent a session that is using a Host Set.';

  create trigger immutable_columns before update on session_host_set_host
    for each row execute procedure immutable_columns('session_id');

  create function cancel_session_with_null_host_source_fk() returns trigger
  as $$
  begin
    if new.host_set_id is null or new.host_id is null then
      perform cancel_session(new.session_id);
      delete from session_host_set_host where session_id = new.session_id;
    end if;
    return new;
  end;
  $$ language plpgsql;
  
  create trigger cancel_session_with_null_host_source_fk after update of host_set_id, host_id on session_host_set_host
    for each row execute procedure cancel_session_with_null_host_source_fk();

  create function insert_session_host_set_host() returns trigger
  as $$
  begin
    if new.host_set_id is null then
      raise exception 'host_set_id is null';
    end if;
    if new.host_id is null then
      raise exception 'host_id is null';
    end if;
    return new;
  end;
  $$ language plpgsql;

  create trigger insert_session_host_set_host before insert on session_host_set_host
    for each row execute procedure insert_session_host_set_host();

  drop view session_list;
  alter table session
    drop constraint session_host_id_fkey,
    drop constraint session_host_set_id_fkey,
    drop column host_id,
    drop column host_set_id
  ;

  -- Replaces trigger from 44/04_sessions.up.sql
  drop trigger insert_session on session;
  create or replace function insert_session() returns trigger
  as $$
  begin
    case
      when new.user_id is null then
        raise exception 'user_id is null';
      when new.target_id is null then
        raise exception 'target_id is null';
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

  create trigger insert_session before insert on session
    for each row execute procedure insert_session();

  -- Replaces view from 59/01_target_ingress_egress_worker_filters.up.sql
  -- Replaced in 64/04_session_list.up.sql
  create view session_list as
  select
    s.public_id,
    s.user_id,
    shsh.host_id,
    s.target_id,
    shsh.host_set_id,
    s.auth_token_id,
    s.project_id,
    s.certificate,
    s.certificate_private_key,
    s.expiration_time,
    s.connection_limit,
    s.tofu_token,
    s.key_id,
    s.termination_reason,
    s.version,
    s.create_time,
    s.update_time,
    s.endpoint,
    s.worker_filter,
    s.egress_worker_filter,
    s.ingress_worker_filter,
    ss.state,
    ss.previous_end_time,
    ss.start_time,
    ss.end_time,
    sc.public_id as connection_id,
    sc.client_tcp_address,
    sc.client_tcp_port,
    sc.endpoint_tcp_address,
    sc.endpoint_tcp_port,
    sc.bytes_up,
    sc.bytes_down,
    sc.closed_reason
  from session s
    join session_state ss on
      s.public_id = ss.session_id
    left join session_connection sc on
      s.public_id = sc.session_id
    left join session_host_set_host shsh on s.public_id = shsh.session_id;

commit;
