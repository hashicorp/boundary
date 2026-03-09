-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(8); -- the number of `is` calls

  -- short form ipv6

  insert into server_controller
  ( private_id,          address)
  values
  ('test-controller-1', '2001:4860:4860::8888');

  select is(count(*), 1::bigint) from server_controller
  where address = '2001:4860:4860::8888';

  update server_controller
    set address = '2001:4860:4860::8844'
  where private_id = 'test-controller-1';

  select is(count(*), 1::bigint) from server_controller
  where address = '2001:4860:4860::8844';

  -- worker

  insert into server_worker
  ( public_id,      scope_id, type, last_status_time, address)
  values
  ('w_________1', 'global', 'pki',  now(),           '2001:4860:4860::8888');

  select is(count(*), 1::bigint) from server_worker
  where address = '2001:4860:4860::8888';

  update server_worker
    set address = '2001:4860:4860::8844'
  where public_id = 'w_________1';

  select is(count(*), 1::bigint) from server_worker
  where address = '2001:4860:4860::8844';

  -- explicit form ipv6

  insert into server_controller
  ( private_id,          address)
  values
  ('test-controller-2', '2001:4860:4860:0:0:0:0:8888');

  select is(count(*), 1::bigint) from server_controller
  where address = '2001:4860:4860:0:0:0:0:8888';

  update server_controller
    set address = '2001:4860:4860:0:0:0:0:8844'
  where private_id = 'test-controller-2';

  select is(count(*), 1::bigint) from server_controller
  where address = '2001:4860:4860:0:0:0:0:8844';

  -- worker

  insert into server_worker
  ( public_id,      scope_id, type, last_status_time, address)
  values
  ('w_________2', 'global', 'pki',  now(),           '2001:4860:4860:0:0:0:0:8888');

  select is(count(*), 1::bigint) from server_worker
  where address = '2001:4860:4860:0:0:0:0:8888';

  update server_worker
    set address = '2001:4860:4860:0:0:0:0:8844'
  where public_id = 'w_________2';

  select is(count(*), 1::bigint) from server_worker
  where address = '2001:4860:4860:0:0:0:0:8844';

rollback;
