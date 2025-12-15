-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  alter table wh_date_dimension
    rename column id to key;

  alter table wh_time_of_day_dimension
    rename column id to key;

  alter table wh_host_dimension
    rename column id to key;

  alter table wh_user_dimension
    rename column id to key;

  alter table wh_session_accumulating_fact
    rename column host_id to host_key;
  alter table wh_session_accumulating_fact
    rename column user_id to user_key;
  alter table wh_session_accumulating_fact
    rename column session_pending_date_id to session_pending_date_key;
  alter table wh_session_accumulating_fact
    rename column session_pending_time_id to session_pending_time_key;
  alter table wh_session_accumulating_fact
    rename column session_active_date_id to session_active_date_key;
  alter table wh_session_accumulating_fact
    rename column session_active_time_id to session_active_time_key;
  alter table wh_session_accumulating_fact
    rename column session_canceling_date_id to session_canceling_date_key;
  alter table wh_session_accumulating_fact
    rename column session_canceling_time_id to session_canceling_time_key;
  alter table wh_session_accumulating_fact
    rename column session_terminated_date_id to session_terminated_date_key;
  alter table wh_session_accumulating_fact
    rename column session_terminated_time_id to session_terminated_time_key;

  alter table wh_session_connection_accumulating_fact
    rename column host_id to host_key;
  alter table wh_session_connection_accumulating_fact
    rename column user_id to user_key;
  alter table wh_session_connection_accumulating_fact
    rename column connection_authorized_date_id to connection_authorized_date_key;
  alter table wh_session_connection_accumulating_fact
    rename column connection_authorized_time_id to connection_authorized_time_key;
  alter table wh_session_connection_accumulating_fact
    rename column connection_connected_date_id to connection_connected_date_key;
  alter table wh_session_connection_accumulating_fact
    rename column connection_connected_time_id to connection_connected_time_key;
  alter table wh_session_connection_accumulating_fact
    rename column connection_closed_date_id to connection_closed_date_key;
  alter table wh_session_connection_accumulating_fact
    rename column connection_closed_time_id to connection_closed_time_key;

  -- rename function from internal/db/schema/migrations/postgres/0/60_wh_domain_types.up.sql
  alter function wh_dim_id rename to wh_dim_key;

  -- rename domain from internal/db/schema/migrations/postgres/0/60_wh_domain_types.up.sql
  alter domain wh_dim_id rename to wh_dim_key;

  -- removes unused function from internal/db/schema/migrations/postgres/0/60_wh_domain_types.up.sql
  drop function wh_current_date_id;

  -- removes unused function from internal/db/schema/migrations/postgres/0/60_wh_domain_types.up.sql
  drop function wh_current_time_id;

  -- rename function from internal/db/schema/migrations/postgres/0/60_wh_domain_types.up.sql
  alter function wh_date_id rename to wh_date_key;

  -- rename function from internal/db/schema/migrations/postgres/0/60_wh_domain_types.up.sql
  alter function wh_time_id rename to wh_time_key;

  -- replaces view from 14/01_wh_user_dimension_oidc.up.sql
  drop view whx_user_dimension_target;
  create view whx_user_dimension_target as
    select key,
           user_id,
           user_name,
           user_description,
           auth_account_id,
           auth_account_type,
           auth_account_name,
           auth_account_description,
           auth_account_external_id,
           auth_account_full_name,
           auth_account_email,
           auth_method_id,
           auth_method_type,
           auth_method_name,
           auth_method_description,
           auth_method_external_id,
           user_organization_id,
           user_organization_name,
           user_organization_description
      from wh_user_dimension
     where current_row_indicator = 'Current'
  ;

  -- replaces function from 14/01_wh_user_dimension_oidc.up.sql
  -- replaced in 82/02_wh_upsert_user_refact.up.sql
  drop function wh_upsert_user;
  create function wh_upsert_user(p_user_id wt_user_id, p_auth_token_id wt_public_id) returns wh_dim_key
  as $$
  declare
    src     whx_user_dimension_target%rowtype;
    target  whx_user_dimension_target%rowtype;
    new_row wh_user_dimension%rowtype;
    acct_id wt_public_id;
  begin
    select auth_account_id into strict acct_id
      from auth_token
     where public_id = p_auth_token_id;

    select * into target
      from whx_user_dimension_target as t
     where t.user_id               = p_user_id
       and t.auth_account_id       = acct_id;

    select target.key, t.* into src
      from whx_user_dimension_source as t
     where t.user_id               = p_user_id
       and t.auth_account_id       = acct_id;

    if src is distinct from target then

      -- expire the current row
      update wh_user_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where user_id               = p_user_id
         and auth_account_id       = acct_id
         and current_row_indicator = 'Current';

      -- insert a new row
      insert into wh_user_dimension (
             user_id,                  user_name,              user_description,
             auth_account_id,          auth_account_type,      auth_account_name,             auth_account_description,
             auth_account_external_id, auth_account_full_name, auth_account_email,
             auth_method_id,           auth_method_type,       auth_method_name,              auth_method_description,
             auth_method_external_id,
             user_organization_id,     user_organization_name, user_organization_description,
             current_row_indicator,    row_effective_time,     row_expiration_time
      )
      select user_id,                  user_name,              user_description,
             auth_account_id,          auth_account_type,      auth_account_name,             auth_account_description,
             auth_account_external_id, auth_account_full_name, auth_account_email,
             auth_method_id,           auth_method_type,       auth_method_name,              auth_method_description,
             auth_method_external_id,
             user_organization_id,     user_organization_name, user_organization_description,
             'Current',                current_timestamp,      'infinity'::timestamptz
        from whx_user_dimension_source
       where user_id               = p_user_id
         and auth_account_id       = acct_id
      returning * into new_row;

      return new_row.key;
    end if;
    return target.key;

  end;
  $$ language plpgsql;

  -- replaces view from 0/65_wh_session_dimensions.up.sql
  drop view whx_host_dimension_target;
  create view whx_host_dimension_target as
  select key,
         host_id,
         host_type,
         host_name,
         host_description,
         host_address,
         host_set_id,
         host_set_type,
         host_set_name,
         host_set_description,
         host_catalog_id,
         host_catalog_type,
         host_catalog_name,
         host_catalog_description,
         target_id,
         target_type,
         target_name,
         target_description,
         target_default_port_number,
         target_session_max_seconds,
         target_session_connection_limit,
         project_id,
         project_name,
         project_description,
         host_organization_id,
         host_organization_name,
         host_organization_description
    from wh_host_dimension
   where current_row_indicator = 'Current'
  ;

  -- replaces function from 0/66_wh_session_dimensions.up.sql
  drop function wh_upsert_host;
  create function wh_upsert_host(p_host_id wt_public_id, p_host_set_id wt_public_id, p_target_id wt_public_id) returns wh_dim_key
  as $$
  declare
    src     whx_host_dimension_target%rowtype;
    target  whx_host_dimension_target%rowtype;
    new_row wh_host_dimension%rowtype;
  begin
    select * into target
      from whx_host_dimension_target as t
     where t.host_id               = p_host_id
       and t.host_set_id           = p_host_set_id
       and t.target_id             = p_target_id;

    select target.key, t.* into src
      from whx_host_dimension_source as t
     where t.host_id               = p_host_id
       and t.host_set_id           = p_host_set_id
       and t.target_id             = p_target_id;

    if src is distinct from target then

      -- expire the current row
      update wh_host_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where host_id               = p_host_id
         and host_set_id           = p_host_set_id
         and target_id             = p_target_id
         and current_row_indicator = 'Current';

      -- insert a new row
      insert into wh_host_dimension (
             host_id,                    host_type,                  host_name,                       host_description,         host_address,
             host_set_id,                host_set_type,              host_set_name,                   host_set_description,
             host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
             target_id,                  target_type,                target_name,                     target_description,
             target_default_port_number, target_session_max_seconds, target_session_connection_limit,
             project_id,                 project_name,               project_description,
             host_organization_id,       host_organization_name,     host_organization_description,
             current_row_indicator,      row_effective_time,         row_expiration_time
      )
      select host_id,                    host_type,                  host_name,                       host_description,         host_address,
             host_set_id,                host_set_type,              host_set_name,                   host_set_description,
             host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
             target_id,                  target_type,                target_name,                     target_description,
             target_default_port_number, target_session_max_seconds, target_session_connection_limit,
             project_id,                 project_name,               project_description,
             host_organization_id,       host_organization_name,     host_organization_description,
             'Current',                  current_timestamp,          'infinity'::timestamptz
        from whx_host_dimension_source
       where host_id               = p_host_id
         and host_set_id           = p_host_set_id
         and target_id             = p_target_id
      returning * into new_row;

      return new_row.key;
    end if;
    return target.key;

  end;
  $$ language plpgsql;

  -- replaces function from 0/69_wh_session_facts.up.sql
  drop trigger wh_insert_session on session;
  drop function wh_insert_session;

  create function wh_insert_session() returns trigger
  as $$
  declare
    new_row wh_session_accumulating_fact%rowtype;
  begin
    with
    pending_timestamp (date_dim_key, time_dim_key, ts) as (
      select wh_date_key(start_time), wh_time_key(start_time), start_time
        from session_state
       where session_id = new.public_id
         and state = 'pending'
    )
    insert into wh_session_accumulating_fact (
           session_id,
           auth_token_id,
           host_key,
           user_key,
           session_pending_date_key,
           session_pending_time_key,
           session_pending_time
    )
    select new.public_id,
           new.auth_token_id,
           wh_upsert_host(new.host_id, new.host_set_id, new.target_id),
           wh_upsert_user(new.user_id, new.auth_token_id),
           pending_timestamp.date_dim_key,
           pending_timestamp.time_dim_key,
           pending_timestamp.ts
      from pending_timestamp
      returning * into strict new_row;
    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session after insert on session
    for each row execute function wh_insert_session();

  -- replaces function from 0/69_wh_session_facts.up.sql
  drop trigger wh_insert_session_connection on session_connection;
  drop function wh_insert_session_connection;

  create function wh_insert_session_connection() returns trigger
  as $$
  declare
    new_row wh_session_connection_accumulating_fact%rowtype;
  begin
    with
    authorized_timestamp (date_dim_key, time_dim_key, ts) as (
      select wh_date_key(start_time), wh_time_key(start_time), start_time
        from session_connection_state
       where connection_id = new.public_id
         and state = 'authorized'
    ),
    session_dimension (host_dim_key, user_dim_key) as (
      select host_key, user_key
        from wh_session_accumulating_fact
       where session_id = new.session_id
    )
    insert into wh_session_connection_accumulating_fact (
           connection_id,
           session_id,
           host_key,
           user_key,
           connection_authorized_date_key,
           connection_authorized_time_key,
           connection_authorized_time,
           client_tcp_address,
           client_tcp_port_number,
           endpoint_tcp_address,
           endpoint_tcp_port_number,
           bytes_up,
           bytes_down
    )
    select new.public_id,
           new.session_id,
           session_dimension.host_dim_key,
           session_dimension.user_dim_key,
           authorized_timestamp.date_dim_key,
           authorized_timestamp.time_dim_key,
           authorized_timestamp.ts,
           new.client_tcp_address,
           new.client_tcp_port,
           new.endpoint_tcp_address,
           new.endpoint_tcp_port,
           new.bytes_up,
           new.bytes_down
      from authorized_timestamp,
           session_dimension
      returning * into strict new_row;
    perform wh_rollup_connections(new.session_id);
    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session_connection after insert on session_connection
    for each row execute function wh_insert_session_connection();

  -- replaces function from 0/69_wh_session_facts.up.sql
  drop trigger wh_insert_session_state on session_state;
  drop function wh_insert_session_state;

  create function wh_insert_session_state() returns trigger
  as $$
  declare
    date_col text;
    time_col text;
    ts_col text;
    q text;
    session_row wh_session_accumulating_fact%rowtype;
  begin
    if new.state = 'pending' then
      -- The pending state is the first state which is handled by the
      -- wh_insert_session trigger. The update statement in this trigger will
      -- fail for the pending state because the row for the session has not yet
      -- been inserted into the wh_session_accumulating_fact table.
      return null;
    end if;

    date_col = 'session_' || new.state || '_date_key';
    time_col = 'session_' || new.state || '_time_key';
    ts_col   = 'session_' || new.state || '_time';

    q = format('update wh_session_accumulating_fact
                   set (%I, %I, %I) = (select wh_date_key(%L), wh_time_key(%L), %L::timestamptz)
                 where session_id = %L
                returning *',
                date_col,       time_col,       ts_col,
                new.start_time, new.start_time, new.start_time,
                new.session_id);
    execute q into strict session_row;

    return null;
  end;
  $$ language plpgsql;

  -- Replaced in 92/02_session_state_tstzrange.up.sql
  create trigger wh_insert_session_state after insert on session_state
    for each row execute function wh_insert_session_state();

  -- replaces function from 0/69_wh_session_facts.up.sql
  drop trigger wh_insert_session_connection_state on session_connection_state;
  drop function wh_insert_session_connection_state;

-- Updated in 90/01_remove_session_connection_state.up.sql
  create function wh_insert_session_connection_state() returns trigger
  as $$
  declare
    date_col text;
    time_col text;
    ts_col text;
    q text;
    connection_row wh_session_connection_accumulating_fact%rowtype;
  begin
    if new.state = 'authorized' then
      -- The authorized state is the first state which is handled by the
      -- wh_insert_session_connection trigger. The update statement in this
      -- trigger will fail for the authorized state because the row for the
      -- session connection has not yet been inserted into the
      -- wh_session_connection_accumulating_fact table.
      return null;
    end if;

    date_col = 'connection_' || new.state || '_date_key';
    time_col = 'connection_' || new.state || '_time_key';
    ts_col   = 'connection_' || new.state || '_time';

    q = format('update wh_session_connection_accumulating_fact
                   set (%I, %I, %I) = (select wh_date_key(%L), wh_time_key(%L), %L::timestamptz)
                 where connection_id = %L
                returning *',
                date_col,       time_col,       ts_col,
                new.start_time, new.start_time, new.start_time,
                new.connection_id);
    execute q into strict connection_row;

    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session_connection_state after insert on session_connection_state
    for each row execute function wh_insert_session_connection_state();

commit;
