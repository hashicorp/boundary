-- Tests that the helper methods for network address dimension work as expected.
begin;
select plan(7);

-- test wh_private_address_status
select is(wh_private_address_indicator('10.0.0.1'::inet), 'Private IP address');
select is(wh_private_address_indicator('192.168.0.1'::inet), 'Private IP address');
select is(wh_private_address_indicator('172.16.0.1'::inet), 'Private IP address');
select is(wh_private_address_indicator('73.2.3.4'::inet), 'Public IP address');
select is(wh_private_address_indicator('2001:4860:4860::8888'::inet), 'Public IP address');
select is(wh_private_address_indicator('fe80::1234:5678:1234:5678'::inet), 'Private IP address');
select is(wh_private_address_indicator(null::inet), 'Not Applicable');

select * from finish();
rollback;