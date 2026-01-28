-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- procedurally rename unique constraints to follow style guide `tablename_col1_colx_uq`
  -- if constraint name format is under 63 characters
  do $$
  declare
    const record;
    i     int;
  begin 
    for const in
        select pc.conname  as constraint_name,
               pgc.relname as table_name,
               pgc.relname || '_' || (
                select string_agg(attname, '_')
                  from (
                    select pa.attname
                      from pg_catalog.pg_attribute pa
                     where pa.attrelid = pc.conrelid
                       and pa.attnum = any(pc.conkey)
                  order by pa.attname asc
                  ) as attname
               ) || '_uq'  as new_name,
               pc.conrelid as table_num,
               pc.conkey   as attr_keys,
               regexp_replace(regexp_replace(pc.conname, '^' || pgc.relname || '_', ''), 'uq$', '') as attrs_concat
          from pg_catalog.pg_constraint pc
          join pg_catalog.pg_class      pgc on pc.conrelid = pgc.oid
         where pgc.relname not like 'pg_%'
           and contype = 'u'
      order by pgc.relname, pc.conname
      loop foreach i in array const.attr_keys 
        loop const.attrs_concat := regexp_replace(
          const.attrs_concat,
          concat((
              select pa.attname
                from pg_catalog.pg_attribute pa
               where pa.attnum = i
                 and pa.attrelid = const.table_num
            ), '_'), '');
        end loop;
        if length(const.attrs_concat) > 0 and length(const.new_name) <= 63
          then
            execute format('alter table %I rename constraint %I to %I', const.table_name, const.constraint_name, const.new_name);
        end if;
      end loop;
  end;
  $$ language plpgsql;

  -- manually rename unique constraints to follow style guide if constraint name format exceeds 63 characters
  alter table auth_password_argon2_conf rename constraint auth_password_argon2_conf_password_method_id_iterations_mem_key
    to auth_password_argon2_conf_iters_thrds_mem_pm_id_key_salt_len_uq;
  alter table auth_password_credential rename constraint auth_password_credential_password_method_id_password_conf_i_key
    to auth_password_credential_password_method_conf_account_ids_uq;
  -- Renames credential from 33/01_static_credential.up.sql
  alter table credential_static_username_password_credential rename constraint credential_static_username_password_store_id_public_id_uq
    to credential_static_username_password_credential_store_pub_ids_uq;
  -- Renames credential from 39/01_static_ssh_private_key_creds.up.sql
  alter table credential_static_ssh_private_key_credential rename constraint credential_static_ssh_private_key_store_id_public_id_uq
    to credential_static_ssh_private_key_credential_store_pub_ids_uq;

  -- procedurally rename foreign key constraints to follow style guide 'reftable_fkey'
  -- if constraint name format is under 63 characters
  do $$
  declare
    const record;
    i     int;
  begin
  for const in
      select pc.conname         as constraint_name,
             pgc.relname        as table_name,
             pgc.relname || '_' as new_name,
             pc.conrelid        as conrelid,
             pc.conkey          as conkey,
             pgc2.relname       as con_table
        from pg_catalog.pg_constraint pc
        join pg_catalog.pg_class      pgc on pc.confrelid = pgc.oid
        join pg_catalog.pg_class      pgc2 on pc.conrelid = pgc2.oid
	     where pgc.relname not like 'pg_%'
         and contype = 'f'
	       and (pc.conname !~ ('^' || pgc.relname || '_')
          or pc.conname !~ 'fkey[1]?$')
	  order by pgc.relname, pc.conname
  loop
    i = (
      select max(x)
        from unnest(const.conkey) as x
    );
    const.new_name = const.new_name || (
      select pa.attname
        from pg_catalog.pg_attribute pa
       where const.conrelid = pa.attrelid
         and pa.attnum = i
    ) || '_fkey';
    if length(const.new_name) <= 63
      then
      begin
        execute format('alter table if exists %I rename constraint %I to %I', const.con_table, const.constraint_name, const.new_name);
      exception when others then
      end;
    end if;
  end loop;
  end;
  $$ language plpgsql;

commit;
