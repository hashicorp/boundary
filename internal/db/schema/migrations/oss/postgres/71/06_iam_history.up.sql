-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create extension if not exists btree_gist;

  create table iam_scope_hst (
    public_id wt_scope_id not null,
    name text null,
    description text null,
    type text not null
      constraint iam_scope_type_enm_fkey
        references iam_scope_type_enm (string)
        on delete restrict
        on update cascade,
    parent_id text null,
    primary_auth_method_id wt_public_id null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint iam_scope_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table iam_scope_hst is
    'iam_scope_hst is a history table where each row contains the values from a row '
    'in the iam_scope table during the time range in the valid_range column.';

  create trigger hst_on_insert after insert on iam_scope
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on iam_scope
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on iam_scope
    for each row execute function hst_on_delete();

  insert into iam_scope_hst
    (public_id, name, description, type, parent_id, primary_auth_method_id)
  select public_id, name, description, type, parent_id, primary_auth_method_id
    from iam_scope;

  create table iam_user_hst (
    public_id wt_user_id not null,
    name text null,
    description text null,
    scope_id wt_scope_id not null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint iam_user_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
  );
  comment on table iam_user_hst is
    'iam_user_hst is a history table where each row contains the values from a row '
    'in the iam_user table during the time range in the valid_range column.';

  create trigger hst_on_insert after insert on iam_user
    for each row execute function hst_on_insert();
  create trigger hst_on_update after update on iam_user
    for each row execute function hst_on_update();
  create trigger hst_on_delete after delete on iam_user
    for each row execute function hst_on_delete();

  insert into iam_user_hst
    (public_id, name, description, scope_id)
  select public_id, name, description, scope_id
    from iam_user;

commit;
