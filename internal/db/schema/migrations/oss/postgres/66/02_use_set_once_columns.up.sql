-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  drop trigger before_soft_delete_credential_vault_store on credential_vault_store;
  drop function before_soft_delete_credential_vault_store;

  create trigger set_once_columns before update on credential_vault_store
    for each row execute procedure set_once_columns('delete_time');

commit;
