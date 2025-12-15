-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(12); -- the number of `is` calls

  -- short form ipv6

  insert into session_connection
  ( public_id,      session_id,     client_tcp_address,     endpoint_tcp_address,   user_client_ip)
  values
  ('sc_________1', 's1_____clare', '2001:4860:4860::8888', '2001:4860:4860::8888', '2001:4860:4860::8888');

  select is(count(*), 1::bigint) from session_connection
  where client_tcp_address = '2001:4860:4860::8888';

  select is(count(*), 1::bigint) from session_connection
  where endpoint_tcp_address = '2001:4860:4860::8888';

  select is(count(*), 1::bigint) from session_connection
  where user_client_ip = '2001:4860:4860::8888';

  update session_connection
    set client_tcp_address = '2001:4860:4860::8844',
      endpoint_tcp_address = '2001:4860:4860::8844',
      user_client_ip       = '2001:4860:4860::8844'
  where public_id = 'sc_________1';

  select is(count(*), 1::bigint) from session_connection
  where client_tcp_address = '2001:4860:4860::8844';

  select is(count(*), 1::bigint) from session_connection
  where endpoint_tcp_address = '2001:4860:4860::8844';

  select is(count(*), 1::bigint) from session_connection
  where user_client_ip = '2001:4860:4860::8844';

  -- explicit form ipv6

  insert into session_connection
  ( public_id,      session_id,     client_tcp_address,            endpoint_tcp_address,          user_client_ip)
  values
  ('sc_________2', 's2_____clare', '2001:4860:4860:0:0:0:0:8888', '2001:4860:4860:0:0:0:0:8888', '2001:4860:4860:0:0:0:0:8888');

  select is(count(*), 1::bigint) from session_connection
  where client_tcp_address = '2001:4860:4860:0:0:0:0:8888';

  select is(count(*), 1::bigint) from session_connection
  where endpoint_tcp_address = '2001:4860:4860:0:0:0:0:8888';

  select is(count(*), 1::bigint) from session_connection
  where user_client_ip = '2001:4860:4860:0:0:0:0:8888';

  update session_connection
    set client_tcp_address = '2001:4860:4860:0:0:0:0:8844',
      endpoint_tcp_address = '2001:4860:4860:0:0:0:0:8844',
      user_client_ip       = '2001:4860:4860:0:0:0:0:8844'
  where public_id = 'sc_________2';

  -- since the col type is inet, postgres actually knows that 2001:4860:4860:0:0:0:0:8844 is
  -- equivalent to 2001:4860:4860::8844 from above, meaning these selects return 2 results

  select is(count(*), 2::bigint) from session_connection
  where client_tcp_address = '2001:4860:4860:0:0:0:0:8844';

  select is(count(*), 2::bigint) from session_connection
  where endpoint_tcp_address = '2001:4860:4860:0:0:0:0:8844';

  select is(count(*), 2::bigint) from session_connection
  where user_client_ip = '2001:4860:4860:0:0:0:0:8844';

rollback;
