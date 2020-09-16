begin;

  drop table session_state;
  drop table session_state_enm;
  drop table session;
  drop table session_termination_reason_enm;
  drop function insert_session_state;
  drop function insert_new_session_state;
  drop function insert_session;
  drop function update_session_state_on_termination_reason;
  drop function insert_session_state;


  delete
  from oplog_ticket
  where name in (
          'session'
      );

commit;
