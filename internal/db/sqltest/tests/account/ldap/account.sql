-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

-- account tests triggers:
--  insert_auth_account_subtype
--  delete_auth_account_subtype

begin;
select plan(8);
select wtt_load('widgets', 'iam', 'kms', 'auth');

-- validate the setup data
select is(count(*), 1::bigint) from auth_ldap_account where public_id = 'ala___walter';
select is(count(*), 1::bigint) from auth_account where public_id = 'ala___walter';

-- validate the insert triggers
prepare insert_ldap_account as
    insert into auth_ldap_account
        (auth_method_id,   public_id,     login_name)
    values
        ('alm___widget',   'ala___tania', 'tania');
select lives_ok('insert_ldap_account');

select is(count(*), 1::bigint) from auth_ldap_account where public_id = 'ala___tania';
select is(count(*), 1::bigint) from auth_account where public_id = 'ala___tania';

-- validate the delete triggers
prepare delete_ldap_account as
    delete
    from auth_ldap_account
    where public_id = 'ala___tania';
select lives_ok('delete_ldap_account');

select is(count(*), 0::bigint) from auth_ldap_account where public_id = 'ala___tania';
select is(count(*), 0::bigint) from auth_account where public_id = 'ala___tania';

select * from finish();
rollback;