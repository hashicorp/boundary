-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  drop trigger wh_insert_stmt_session_credential_dynamic on session_credential_dynamic;
  drop function wh_upsert_credentail_group;

  -- wh_upsert_credential_group determines if a new wh_credential_group needs to be
  -- created due to changes to the coresponding wh_credential_dimensions. It then
  -- updates the wh_session_accumulating_fact to associate it with the correct wh_credential_group.
  -- Replaces function in 16/03_wh_credential_dimension
  create function wh_upsert_credential_group() returns trigger
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
         and current_row_indicator = 'Current'
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
           and current_row_indicator = 'Current'
      loop
        insert into wh_credential_group_membership
          (credential_group_key, credential_key)
        values
          (cg_key,               c_key);
      end loop;
    end if;

    update wh_session_accumulating_fact
      set credential_group_key = cg_key
    where session_id = s_id;

    return null;
  end;
  $$ language plpgsql;

  create trigger wh_insert_stmt_session_credential_dynamic after insert on session_credential_dynamic
    referencing new table as new_table
    for each statement execute function wh_upsert_credential_group();

commit;
