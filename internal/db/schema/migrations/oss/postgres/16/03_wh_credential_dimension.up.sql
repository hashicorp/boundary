-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- wh_upsert_credential_dimension compares the current vaules in the wh_credential_dimension
  -- with the current values in the operational tables for the given parameters. IF the values
  -- between operational tables and the wh_credential_dimension differ, a new row is inserted in
  -- the wh_credential_dimension to match the current values in the operational tables.
  -- Replaced in 63/03_wh_ssh_cert_library.up.sql
  create function wh_upsert_credential_dimension(p_session_id wt_public_id, p_library_id wt_public_id, p_credential_purpose wh_dim_text) returns wh_dim_key
  as $$
  declare
    src     whx_credential_dimension_target%rowtype;
    target  whx_credential_dimension_target%rowtype;
    new_row wh_credential_dimension%rowtype;
    t_id    wt_public_id;
  begin
    select s.target_id into strict t_id
      from session as s
     where s.public_id = p_session_id;

    select * into target
      from whx_credential_dimension_target as t
     where t.credential_library_id = p_library_id
       and t.target_id             = t_id
       and t.credential_purpose    = p_credential_purpose;

    select
      target.key,              t.credential_purpose,
      t.credential_library_id, t.credential_library_type, t.credential_library_name, t.credential_library_description, t.credential_library_vault_path,    t.credential_library_vault_http_method, t.credential_library_vault_http_request_body,
      t.credential_store_id,   t.credential_store_type,   t.credential_store_name,   t.credential_store_description,   t.credential_store_vault_namespace, t.credential_store_vault_address,
      t.target_id,             t.target_type,             t.target_name,             t.target_description,             t.target_default_port_number,       t.target_session_max_seconds,           t.target_session_connection_limit,
      t.project_id,            t.project_name,            t.project_description,
      t.organization_id,       t.organization_name,       t.organization_description
      into src
      from whx_credential_dimension_source as t
     where t.credential_library_id = p_library_id
       and t.session_id            = p_session_id
       and t.target_id             = t_id
       and t.credential_purpose    = p_credential_purpose;

    if src is distinct from target then
      update wh_credential_dimension
         set current_row_indicator = 'Expired',
             row_expiration_time   = current_timestamp
       where credential_library_id = p_library_id
         and target_id             = t_id
         and credential_purpose    = p_credential_purpose
         and current_row_indicator = 'Current';

      insert into wh_credential_dimension (
             credential_purpose,
             credential_library_id, credential_library_type, credential_library_name,  credential_library_description, credential_library_vault_path,    credential_library_vault_http_method, credential_library_vault_http_request_body,
             credential_store_id,   credential_store_type,   credential_store_name,    credential_store_description,   credential_store_vault_namespace, credential_store_vault_address,
             target_id,             target_type,             target_name,              target_description,             target_default_port_number,       target_session_max_seconds,           target_session_connection_limit,
             project_id,            project_name,            project_description,
             organization_id,       organization_name,       organization_description,
             current_row_indicator, row_effective_time,      row_expiration_time
      )
      select credential_purpose,
             credential_library_id, credential_library_type, credential_library_name,  credential_library_description, credential_library_vault_path,    credential_library_vault_http_method, credential_library_vault_http_request_body,
             credential_store_id,   credential_store_type,   credential_store_name,    credential_store_description,   credential_store_vault_namespace, credential_store_vault_address,
             target_id,             target_type,             target_name,              target_description,             target_default_port_number,       target_session_max_seconds,           target_session_connection_limit,
             project_id,            project_name,            project_description,
             organization_id,       organization_name,       organization_description,
             'Current',             current_timestamp,       'infinity'::timestamptz
        from whx_credential_dimension_source
       where credential_library_id = p_library_id
         and session_id            = p_session_id
         and target_id             = t_id
         and credential_purpose    = p_credential_purpose
      returning * into new_row;

      return new_row.key;
    end if;

    return target.key;
  end
  $$ language plpgsql;

  -- Run wh_upsert_credential_dimension for session_credential_dynamic row that is inserted.
  create function wh_insert_session_credential_dynamic() returns trigger
  as $$
  begin
    perform wh_upsert_credential_dimension(new.session_id, new.library_id, new.credential_purpose);
    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_session_credential_dynamic after insert on session_credential_dynamic
    for each row execute function wh_insert_session_credential_dynamic();

  -- wh_upsert_credentail_group determines if a new wh_credential_group needs to be
  -- created due to changes to the coresponding wh_credential_dimensions. It then
  -- updates the wh_session_accumulating_fact to associate it with the correct wh_credential_group.
  -- Replaced in 61/01_fix_wh_upsert_credential_group
  create function wh_upsert_credentail_group() returns trigger
  as $$
  declare
    cg_key wh_dim_key;
    t_id   wt_public_id;
    s_id   wt_public_id;
    c_key  wh_dim_key;
  begin
    select distinct scd.session_id into strict s_id
      from new_table as scd;

    select distinct s.target_id into strict t_id
           from new_table as scd
      left join session   as s   on s.public_id = scd.session_id;

    -- based on query written by Michele Gaffney
    with
    credential_list (key) as (
      select key
        from wh_credential_dimension
       where target_id = t_id
         and credential_library_id in (select credential_library_id from new_table)
    )
    select distinct credential_group_key into cg_key
      from wh_credential_group_membership a
     where a.credential_key in (select key from credential_list)
       and (select count(key) from credential_list) =
           (
            select count(b.credential_key)
              from wh_credential_group_membership b
             where a.credential_key = b.credential_key
               and b.credential_key in (select key from credential_list)
           )
       and not exists
           (
            select 1
              from wh_credential_group_membership b
             where a.credential_key = b.credential_key
               and b.credential_key not in (select key from credential_list)
           )
    ;
    if cg_key is null then
      insert into wh_credential_group default values returning key into cg_key;
      for c_key in
        select key
          from wh_credential_dimension
         where target_id = t_id
           and credential_library_id in (select credential_library_id from new_table)
      loop
        insert into wh_credential_group_membership
          (credential_group_key, credential_key)
        values
          (cg_key,               c_key);
      end loop;
    end if;

    update wh_session_connection_accumulating_fact
      set credential_group_key = cg_key
    where session_id = s_id;

    return null;
  end;
  $$ language plpgsql;

  -- Run wh_upsert_credentail_group on statement. This assumes that all relevant
  -- session_credential_dynamic rows are inserted as a single statement and that
  -- the wh_insert_session_credential_dynamic trigger ran for each row and updated
  -- the wh_credential_dimensions. Then this statement trigger can run to update the
  -- bridge tables and wh_session_accumulating_fact.
  create trigger wh_insert_stmt_session_credential_dynamic after insert on session_credential_dynamic
    referencing new table as new_table
    for each statement execute function wh_upsert_credentail_group();

commit;
