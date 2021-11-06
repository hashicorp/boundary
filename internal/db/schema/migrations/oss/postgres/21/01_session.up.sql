begin;

alter table session_connection
  add column user_client_ip inet not null default '::';

commit;