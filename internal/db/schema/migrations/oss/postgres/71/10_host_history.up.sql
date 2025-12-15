-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table host_history_base (
    history_id wt_url_safe_id primary key
  );
  comment on table host_history_base is
    'host_history_base is a base history table '
    'for host history tables.';

  create function insert_host_history_subtype() returns trigger
  as $$
  begin
    insert into host_history_base
      (history_id)
    values
      (new.history_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_host_history_subtype is
    'insert_host_history_subtype is a before insert trigger '
    'function for subtypes of host_history_base.';

  create function delete_host_history_subtype() returns trigger
  as $$
  begin
    delete
      from host_history_base
     where history_id = old.history_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;
  comment on function delete_host_history_subtype is
    'delete_host_history_subtype() is an after delete trigger '
    'function for subtypes of host_history_base.';

  create table no_host_history (
    history_id wt_url_safe_id primary key
      constraint host_history_base_fkey
        references host_history_base (history_id)
        on delete restrict
        on update restrict
  );
  comment on table no_host_history is
    'no_host_history is a table with one row to represent '
    'the case of a target with a direct address associated to it.';

  insert into host_history_base values ('_______none');
  insert into no_host_history values ('_______none');

  create trigger immutable_table before insert or update or delete on no_host_history
    for each row execute procedure immutable_table();

  create table static_host_hst (
    public_id wt_public_id not null,
    name text null,
    description text null,
    catalog_id wt_public_id not null,
    address text not null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint host_history_base_fkey
        references host_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint static_host_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table static_host_hst is
    'static_host_hst is a history table where each row contains the values from a row '
    'in the static_host table during the time range in the valid_range column.';

  create trigger insert_host_history_subtype before insert on static_host_hst
    for each row execute function insert_host_history_subtype();
  create trigger delete_host_history_subtype after delete on static_host_hst
    for each row execute function delete_host_history_subtype();

  create trigger hst_on_insert after insert on static_host
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on static_host
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on static_host
    for each row execute function hst_on_delete();

  insert into static_host_hst
        (public_id, name, description, catalog_id, address)
  select public_id, name, description, catalog_id, address
    from static_host;

  create table host_plugin_host_hst (
    public_id wt_public_id not null,
    name wt_name null,
    description text null,
    catalog_id wt_public_id not null,
    external_id text not null,
    external_name text null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint host_history_base_fkey
        references host_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint host_plugin_host_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table host_plugin_host_hst is
    'host_plugin_host_hst is a history table where each row contains the values from a row '
    'in the host_plugin_host table during the time range in the valid_range column.';

  create trigger insert_host_history_subtype before insert on host_plugin_host_hst
    for each row execute function insert_host_history_subtype();
  create trigger delete_host_history_subtype after delete on host_plugin_host_hst
    for each row execute function delete_host_history_subtype();

  create trigger hst_on_insert after insert on host_plugin_host
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on host_plugin_host
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on host_plugin_host
    for each row execute function hst_on_delete();

  insert into host_plugin_host_hst
        (public_id, name, description, catalog_id, external_id, external_name)
  select public_id, name, description, catalog_id, external_id, external_name
    from host_plugin_host;

commit;
