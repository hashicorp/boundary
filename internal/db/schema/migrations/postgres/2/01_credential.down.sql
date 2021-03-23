begin;

  drop function delete_credential_dynamic_subtype;
  drop function insert_credential_dynamic_subtype;
  drop table credential_dynamic;

  drop function delete_credential_static_subtype;
  drop function insert_credential_static_subtype;
  drop table credential_static;

  drop function delete_credential_subtype;
  drop function insert_credential_subtype;
  drop table credential;

  drop function delete_credential_library_subtype;
  drop function insert_credential_library_subtype;
  drop table credential_library;

  drop function delete_credential_store_subtype;
  drop function insert_credential_store_subtype;
  drop table credential_store;

commit;
