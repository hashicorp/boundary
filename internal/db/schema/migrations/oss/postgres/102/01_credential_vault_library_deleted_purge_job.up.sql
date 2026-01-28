-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- The credential_vault_library_deleted table was renamed to
  -- credential_vault_generic_library_deleted in
  -- 99/01_credential_vault_library_refactor.up.sql, but the corresponding
  -- legacy purge job was not deleted. This migration deletes that legacy job.
  -- The new job that takes over the legacy one is
  -- credential_vault_generic_library_deleted_items_table_purge.
  delete from job where name = 'credential_vault_library_deleted_items_table_purge';
commit;