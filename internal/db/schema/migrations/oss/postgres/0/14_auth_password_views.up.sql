-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- auth_password_conf_union is a union of the configuration settings
  -- of all supported key derivation functions.
  -- It will be updated as new key derivation functions are supported.
  create or replace view auth_password_conf_union as
      -- Do not change the order of the columns when adding new configurations.
      -- Union with new tables appending new columns as needed.
      select c.password_method_id, c.private_id as password_conf_id, c.private_id,
             'argon2' as conf_type,
             c.iterations, c.memory, c.threads, c.salt_length, c.key_length
        from auth_password_argon2_conf c;

  -- auth_password_current_conf provides a view of the current password
  -- configuration for each password auth method.
  -- The view will be updated as new key derivation functions are supported
  -- but the query to create the view should not need to be updated.
  create or replace view auth_password_current_conf as
      -- Rerun this query whenever auth_password_conf_union is updated.
      select pm.min_login_name_length, pm.min_password_length, c.*
        from auth_password_method pm
  inner join auth_password_conf_union c
          on pm.password_conf_id = c.password_conf_id;

commit;
