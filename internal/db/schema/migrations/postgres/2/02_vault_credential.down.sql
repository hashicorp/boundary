begin;

  delete from oplog_ticket
   where name in ('vault_credential_library',
                  'vault_credential_store',
                  'vault_credential_lease');

  drop table vault_credential_lease;
  drop table vault_credential_token;
  drop table vault_credential_library;
  drop table vault_client_certificate;
  drop table vault_credential_store;

commit;

