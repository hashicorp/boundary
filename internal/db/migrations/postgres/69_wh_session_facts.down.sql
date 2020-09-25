begin;

  drop trigger update_wh_session_connection_fact on session_connection;
  drop function update_wh_session_connection_fact;

  drop trigger insert_wh_session_connection_fact on session_connection;
  drop function insert_wh_session_connection_fact;

  drop trigger insert_wh_session_fact on session;
  drop function insert_wh_session_fact;

  drop function rollup_connections;

commit;
