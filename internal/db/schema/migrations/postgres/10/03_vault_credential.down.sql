begin;

  drop view credential_vault_library_private;
  drop view credential_vault_store_public;
  drop view credential_vault_store_private;

  delete from oplog_ticket
   where name in ('credential_vault_library',
                  'credential_vault_store',
                  'credential_vault_credential');

  drop table credential_vault_credential;
  drop table credential_vault_credential_status_enm;
  drop table credential_vault_library;
  drop table credential_vault_http_method_enm;
  drop table credential_vault_client_certificate;
  drop table credential_vault_token;
  drop table credential_vault_token_status_enm;
  drop table credential_vault_store;

  drop function insert_credential_vault_token;

commit;

