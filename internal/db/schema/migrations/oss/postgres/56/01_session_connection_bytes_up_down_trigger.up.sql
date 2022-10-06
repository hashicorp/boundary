begin;

create or replace function prevent_bytes_update_on_closed_connection() returns trigger
as $$
begin
  if old.closed_reason is not null then
    -- ignore new bytes_up and bytes_down
    new.bytes_up := old.bytes_up;
    new.bytes_down := old.bytes_down;
  end if;
  return new; -- any other fields are updated
end;
$$ language plpgsql;
comment on function prevent_bytes_update_on_closed_connection is
  'The last update of bytes_up and bytes_down for any session_connection should
  be the one that happens as the consequence of a connection closure
  (when closed_reason is also set). This function ensures those fields cannot
  be updated past connection closure';

create trigger update_connection_bytes before update of bytes_up, bytes_down on session_connection
  for each row execute procedure prevent_bytes_update_on_closed_connection();

commit;
