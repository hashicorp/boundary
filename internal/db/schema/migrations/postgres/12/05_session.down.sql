begin;

  drop trigger revoke_credentials on session_state;
  drop function revoke_credentials;
  drop table session_credential_dynamic;

commit;
