-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- test the upsert network address dimension function
begin;
  select plan(4);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts');

  select is(wh_upsert_network_address_dimension('non-existent-key'), 'No Addresses');

  -- The network address group key remains the same for the same set of
  -- addresses.
  with nag (key) as (
    select wh_upsert_network_address_dimension('h_____wb__03')
  )
  select is(wh_upsert_network_address_dimension('h_____wb__03'), key) from nag;
  with nag (key) as (
    select wh_upsert_network_address_dimension('h_____wb__03')
  )
  select is(wh_upsert_network_address_dimension('h_____wb__03-plgh'), key) from nag;

  -- different set of addresses means a different group key
  with nag (key) as (
    select wh_upsert_network_address_dimension('h_____wb__01')
  )
  select isnt(wh_upsert_network_address_dimension('h_____wb__02'), key) from nag;

   select * from finish();
rollback;
