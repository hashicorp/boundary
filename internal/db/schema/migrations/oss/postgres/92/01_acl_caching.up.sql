-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- This will default to a bigint with a start value of 1 and no max
  create sequence acl_cache_version_seq;

  create function update_acl_cache_on_insert_version_seq() returns trigger
  as $$
  declare
    version bigint;
  begin
    select nextval('acl_cache_version_seq') into version;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_acl_cache_on_insert_version_seq() is
    'function used in before insert triggers to ensure the cache version is updated';

  create function update_acl_cache_on_delete_version_seq() returns trigger
  as $$
  declare
    version bigint;
  begin
    select nextval('acl_cache_version_seq') into version;
    return old;
  end;
  $$ language plpgsql;
  comment on function update_acl_cache_on_delete_version_seq() is
    'function used in after delete triggers to ensure the cache version is updated';

  create trigger iam_group_member_user_acl_cache_version_seq_bef_ins_trigger
  before
  insert on iam_group_member_user
    for each statement execute procedure update_acl_cache_on_insert_version_seq();

  create trigger iam_group_member_user_acl_cache_version_seq_aft_del_trigger
  after
  delete on iam_group_member_user
    for each statement execute procedure update_acl_cache_on_delete_version_seq();

  create trigger auth_managed_group_member_account_acl_cache_version_seq_bef_ins_trigger
  before
  insert on auth_managed_group_member_account
    for each statement execute procedure update_acl_cache_on_insert_version_seq();

  create trigger auth_managed_group_member_account_acl_cache_version_seq_aft_del_trigger
  after
  delete on auth_managed_group_member_account
    for each statement execute procedure update_acl_cache_on_delete_version_seq();

  create trigger iam_user_role_acl_cache_version_seq_bef_ins_trigger
  before
  insert on iam_user_role
    for each statement execute procedure update_acl_cache_on_insert_version_seq();

  create trigger iam_user_role_acl_cache_version_seq_aft_del_trigger
  after
  delete on iam_user_role
    for each statement execute procedure update_acl_cache_on_delete_version_seq();

  create trigger iam_group_role_acl_cache_version_seq_bef_ins_trigger
  before
  insert on iam_group_role
    for each statement execute procedure update_acl_cache_on_insert_version_seq();

  create trigger iam_group_role_acl_cache_version_seq_aft_del_trigger
  after
  delete on iam_group_role
    for each statement execute procedure update_acl_cache_on_delete_version_seq();

  create trigger iam_managed_group_role_acl_cache_version_seq_bef_ins_trigger
  before
  insert on iam_managed_group_role
    for each statement execute procedure update_acl_cache_on_insert_version_seq();

  create trigger iam_managed_group_role_acl_cache_version_seq_aft_del_trigger
  after
  delete on iam_managed_group_role
    for each statement execute procedure update_acl_cache_on_delete_version_seq();

  create trigger iam_role_grant_acl_cache_version_seq_bef_ins_trigger
  before
  insert on iam_role_grant
    for each statement execute procedure update_acl_cache_on_insert_version_seq();

  create trigger iam_role_grant_acl_cache_version_seq_aft_del_trigger
  after
  delete on iam_role_grant
    for each statement execute procedure update_acl_cache_on_delete_version_seq();

  create trigger iam_role_grant_scope_acl_cache_version_seq_bef_ins_trigger
  before
  insert on iam_role_grant_scope
    for each statement execute procedure update_acl_cache_on_insert_version_seq();

  create trigger iam_role_grant_scope_acl_cache_version_seq_aft_del_trigger
  after
  delete on iam_role_grant_scope
    for each statement execute procedure update_acl_cache_on_delete_version_seq();

commit;