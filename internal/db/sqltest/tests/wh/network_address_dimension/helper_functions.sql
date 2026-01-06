-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- Tests that the helper methods for network address dimension work as expected.
begin;
select plan(33);

-- test wh_private_address_status
select is(wh_private_address_indicator('10.0.0.1'::inet), 'Private IP address');
select is(wh_private_address_indicator('192.168.0.1'::inet), 'Private IP address');
select is(wh_private_address_indicator('172.16.0.1'::inet), 'Private IP address');
select is(wh_private_address_indicator('73.2.3.4'::inet), 'Public IP address');
select is(wh_private_address_indicator('2001:4860:4860::8888'::inet), 'Public IP address');
select is(wh_private_address_indicator('fe80::1234:5678:1234:5678'::inet), 'Private IP address');
select is(wh_private_address_indicator(null::inet), null);

-- test wh_try_cast_inet
-- ipv4
select is(wh_try_cast_inet('127.0.0.1'), '127.0.0.1'::inet);
select is(wh_try_cast_inet('1.2.3.4'), '1.2.3.4'::inet);
select is(wh_try_cast_inet('0.0.0.0'), '0.0.0.0'::inet);

select is(wh_try_cast_inet('1.2.3'), null::inet);
select is(wh_try_cast_inet('256.256.256.256'), null::inet);
select is(wh_try_cast_inet(null), null::inet);

select is(wh_try_cast_inet('not.an.ip.address'), null::inet);
select is(wh_try_cast_inet('not even a dns name'), null::inet);

-- ipv6
select is(wh_try_cast_inet('fe80::1234:1234:1234:1234'), 'fe80::1234:1234:1234:1234'::inet);
select is(wh_try_cast_inet('2001:0db8:0000:0000:0000:ff00:0042:8329'), '2001:0db8:0000:0000:0000:ff00:0042:8329'::inet);
select is(wh_try_cast_inet('2001:db8:0:0:0:ff00:42:8329'), '2001:db8:0:0:0:ff00:42:8329'::inet);
select is(wh_try_cast_inet('0000:0000:0000:0000:0000:0000:0000:0001'), '0000:0000:0000:0000:0000:0000:0000:0001'::inet);
select is(wh_try_cast_inet('::1'), '::1'::inet);
select is(wh_try_cast_inet('::'), '::'::inet);
select is(wh_try_cast_inet('::ffff:129.144.52.38'), '::ffff:129.144.52.38'::inet);
select is(wh_try_cast_inet('::129.144.52.38'), '::129.144.52.38'::inet);
select is(wh_try_cast_inet('::ffff:d'), '::ffff:d'::inet);
select is(wh_try_cast_inet('1080:0:0:0:8:800:200c:417a'), '1080:0:0:0:8:800:200c:417a'::inet);
select is(wh_try_cast_inet('::129.144.52.38'), '::129.144.52.38'::inet);
select is(wh_try_cast_inet('0:0:0:0:0:0:192.1.56.11'), '0:0:0:0:0:0:192.1.56.11'::inet);
select is(wh_try_cast_inet('abcd:abcd:abcd:abcd:abcd:abcd:192.168.158.190'), 'abcd:abcd:abcd:abcd:abcd:abcd:192.168.158.190'::inet);
select is(wh_try_cast_inet('::ffff:192.1.56.10'), '::ffff:192.1.56.10'::inet);

select is(wh_try_cast_inet('::ffff:d.d.d'), null::inet);
select is(wh_try_cast_inet('::ffff:d.d'), null::inet);
select is(wh_try_cast_inet('::d.d.d'), null::inet);
select is(wh_try_cast_inet('::d.d'), null::inet);

select * from finish();
rollback;