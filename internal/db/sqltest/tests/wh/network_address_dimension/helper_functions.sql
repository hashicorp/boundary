-- Tests that the helper methods for network address dimension work as expected.
begin;
select plan(11);

-- test wh_try_cast_inet
select is(wh_try_cast_inet('127.0.0.1'), '127.0.0.1'::inet);
select is(wh_try_cast_inet('fe80::1234:1234:1234:1234'), 'fe80::1234:1234:1234:1234'::inet);
select is(wh_try_cast_inet('not.an.ip.address'), null::inet);
select is(wh_try_cast_inet('not even a dns name'), null::inet);

-- test wh_private_address_status
select is(wh_private_address_status('10.0.0.1'::inet), 'Private');
select is(wh_private_address_status('192.168.0.1'::inet), 'Private');
select is(wh_private_address_status('172.16.0.1'::inet), 'Private');
select is(wh_private_address_status('73.2.3.4'::inet), 'Public');
select is(wh_private_address_status('2001:4860:4860::8888'::inet), 'Public');
select is(wh_private_address_status('fe80::1234:5678:1234:5678'::inet), 'Private');
select is(wh_private_address_status(null::inet), 'Public');

select * from finish();
rollback;