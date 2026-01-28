-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- account tests triggers:
--  insert_auth_account_subtype
--  delete_auth_account_subtype

begin;
select plan(8);
select wtt_load('widgets', 'iam', 'kms', 'auth');

-- validate the setup data
select is(count(*), 1::bigint) from auth_password_account where public_id = 'apa___walter';
select is(count(*), 1::bigint) from auth_account where public_id = 'apa___walter';

-- validate the insert triggers
prepare insert_password_account as
    insert into auth_password_account
    (auth_method_id,     public_id,    login_name)
    values
        ('apm___widget',   'apa___tania', 'tania');
select lives_ok('insert_password_account');

select is(count(*), 1::bigint) from auth_password_account where public_id = 'apa___tania';
select is(count(*), 1::bigint) from auth_account where public_id = 'apa___tania';

-- validate the delete triggers
prepare delete_password_account as
    delete
    from auth_password_account
    where public_id = 'apa___tania';
select lives_ok('delete_password_account');

select is(count(*), 0::bigint) from auth_password_account where public_id = 'apa___tania';
select is(count(*), 0::bigint) from auth_account where public_id = 'apa___tania';

select * from finish();
rollback;
