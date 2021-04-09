begin;

  delete from oplog_ticket
   where name in ('credential_vault_library',
                  'credential_vault_store',
                  'credential_vault_lease');

  drop table credential_vault_lease;
  drop table credential_vault_library;
  drop table credential_vault_client_certificate;
  drop table credential_vault_token;
  drop table credential_vault_token_status_enm;
  drop table credential_vault_store;

commit;

