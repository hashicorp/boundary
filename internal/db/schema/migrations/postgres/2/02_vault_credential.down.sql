begin;

  delete from oplog_ticket where name = 'vault_credential_library';
  delete from oplog_ticket where name = 'vault_credential_store';

  drop table vault_credential_lease;
  drop table vault_credential_token;
  drop table vault_credential_library;
  drop table vault_credential_store;

commit;
