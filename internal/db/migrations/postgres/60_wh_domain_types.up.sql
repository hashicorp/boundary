begin;

  create extension if not exists "pgcrypto";

  create domain wh_inet_port as integer
  check(
    value > 0
    and
    value <= 65535
  );
  comment on domain wh_inet_port is
  'An ordinal number between 1 and 65535 representing a network port';

  create domain wh_bytes_transmitted as bigint
  check(
    value >= 0
  );
  comment on domain wh_bytes_transmitted is
  'A non-negative integer representing the number of bytes transmitted';

  create or replace function wh_dim_id()
    returns text
  as $$
  begin
    return encode(digest(gen_random_bytes(16), 'sha256'), 'base64');
  end;
  $$ language plpgsql;

  create domain wh_dim_id as text
  check(
    length(trim(value)) > 0
  );
  comment on domain wh_dim_id is
  'Random ID generated with pgcrypto';

commit;
