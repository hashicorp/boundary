-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  select plan(4); -- the number of `is` calls

  -- short form ipv6

  insert into static_host_hst
  ( catalog_id,     public_id,      address)
  values
  ('hc__st_____b', 'h___st____bx', '2001:4860:4860::8888');

  select is(count(*), 1::bigint) from static_host_hst
  where address = '2001:4860:4860::8888';

  update static_host_hst
    set address = '2001:4860:4860::8844'
  where public_id = 'h___st____bx';

  select is(count(*), 1::bigint) from static_host_hst
  where address = '2001:4860:4860::8844';

  -- explicit form ipv6

  insert into static_host_hst
  ( catalog_id,     public_id,      address)
  values
  ('hc__st_____b', 'h___st____by', '2001:4860:4860:0:0:0:0:8888');

  select is(count(*), 1::bigint) from static_host_hst
  where address = '2001:4860:4860:0:0:0:0:8888';

  update static_host_hst
    set address = '2001:4860:4860:0:0:0:0:8844'
  where public_id = 'h___st____by';

  select is(count(*), 1::bigint) from static_host_hst
  where address = '2001:4860:4860:0:0:0:0:8844';

rollback;
