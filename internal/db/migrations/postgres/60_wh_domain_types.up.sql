begin;

  -- port
  -- bytes non-negative

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

commit;
