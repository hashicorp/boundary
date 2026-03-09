-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create trigger insert_role_subtype before insert on iam_role_global
    for each row execute procedure insert_role_subtype();

  create trigger insert_grant_scope_update_time before insert on iam_role_global
    for each row execute procedure insert_grant_scope_update_time();

  create trigger insert_grant_this_role_scope_update_time before insert on iam_role_global
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger update_iam_role_global_grant_scope_update_time before update on iam_role_global
    for each row execute procedure insert_grant_scope_update_time();

  create trigger update_iam_role_global_grant_this_role_scope_update_time before update on iam_role_global
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger update_iam_role_global_base_table_update_time after update on iam_role_global
    for each row execute procedure update_iam_role_table_update_time();

  create trigger delete_iam_role_subtype after delete on iam_role_global
    for each row execute procedure delete_iam_role_subtype();

  create trigger default_create_time_column before insert on iam_role_global
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on iam_role_global
    for each row execute procedure update_time_column();

  create trigger update_version_column after update on iam_role_global
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on iam_role_global
    for each row execute procedure immutable_columns('scope_id', 'create_time');

  create trigger default_create_time_column before insert on iam_role_global_individual_org_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on iam_role_global_individual_org_grant_scope
    for each row execute procedure immutable_columns('role_id', 'scope_id', 'grant_scope', 'create_time');

  create trigger default_create_time_column before insert on iam_role_global_individual_project_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on iam_role_global_individual_project_grant_scope
    for each row execute procedure immutable_columns('role_id', 'scope_id', 'create_time');

  create trigger insert_role_subtype before insert on iam_role_org
    for each row execute procedure insert_role_subtype();

  create trigger insert_iam_role_org_grant_scope_update_time before insert on iam_role_org
    for each row execute procedure insert_grant_scope_update_time();

  create trigger insert_iam_role_org_grant_this_role_scope_update_time before insert on iam_role_org
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger update_iam_role_org_grant_scope_update_time before update on iam_role_org
    for each row execute procedure insert_grant_scope_update_time();

  create trigger update_iam_role_org_grant_this_role_scope_update_time before update on iam_role_org
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger update_iam_role_org_base_table_update_time after update on iam_role_org
    for each row execute procedure update_iam_role_table_update_time();

  create trigger delete_iam_role_subtype after delete on iam_role_org
    for each row execute procedure delete_iam_role_subtype();

  create trigger default_create_time_column before insert on iam_role_org
    for each row execute procedure default_create_time();

  create trigger update_time_column before update on iam_role_org
    for each row execute procedure update_time_column();

  create trigger update_version_column after update on iam_role_org
    for each row execute procedure update_version_column();

  create trigger immutable_columns before update on iam_role_org
    for each row execute procedure immutable_columns('scope_id', 'create_time');

  create trigger default_create_time_column before insert on iam_role_org_individual_grant_scope
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on iam_role_org_individual_grant_scope
    for each row execute procedure immutable_columns('role_id', 'grant_scope', 'scope_id', 'create_time');

  create trigger ensure_project_belongs_to_role_org before insert or update on iam_role_org_individual_grant_scope
    for each row execute procedure ensure_project_belongs_to_role_org();

  create trigger insert_role_subtype before insert on iam_role_project
    for each row execute procedure insert_role_subtype();

  create trigger default_create_time_column before insert on iam_role_project
    for each row execute procedure default_create_time();
  
  create trigger update_time_column before update on iam_role_project
    for each row execute procedure update_time_column();

  create trigger update_version_column after update on iam_role_project
    for each row execute procedure update_version_column();

  create trigger update_iam_role_project_base_table_update_time after update on iam_role_project
    for each row execute procedure update_iam_role_table_update_time();

  create trigger delete_iam_role_subtype after delete on iam_role_project
    for each row execute procedure delete_iam_role_subtype();

  create trigger insert_iam_role_project_grant_this_role_scope_update_time before insert on iam_role_project
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger update_iam_role_project_grant_this_role_scope_update_time before update on iam_role_project
    for each row execute procedure insert_grant_this_role_scope_update_time();

  create trigger immutable_columns before update on iam_role_project
    for each row execute procedure immutable_columns('scope_id', 'create_time');

  create trigger set_resource before insert on iam_grant
    for each row execute procedure set_resource();

  create trigger upsert_canonical_grant before insert on iam_role_grant
    for each row execute procedure upsert_canonical_grant();

commit;