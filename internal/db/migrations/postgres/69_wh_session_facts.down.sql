begin;

  drop trigger wh_update_session_connection on session_connection;
  drop function wh_update_session_connection;

  drop trigger wh_insert_session_connection on session_connection;
  drop function wh_insert_session_connection;

  drop trigger wh_insert_session on session;
  drop function wh_insert_session;

  drop function wh_rollup_connections;

commit;
