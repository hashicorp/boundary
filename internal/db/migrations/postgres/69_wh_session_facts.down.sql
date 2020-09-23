begin;

  drop trigger insert_wh_session_fact on session;
  drop function insert_wh_session_fact;

commit;
