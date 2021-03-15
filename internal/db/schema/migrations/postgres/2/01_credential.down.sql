begin;

  delete from oplog_ticket where name = 'credential_library';
  delete from oplog_ticket where name = 'credential_store';

  drop function delete_credential_library_subtype;
  drop function insert_credential_library_subtype;
  drop table credential_library;

  drop function delete_credential_store_subtype;
  drop function insert_credential_store_subtype;
  drop table credential_store;

commit;
