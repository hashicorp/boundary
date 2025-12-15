-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- account tests triggers:
--  insert_auth_account_subtype
--  delete_auth_account_subtype

begin;
select plan(8);
select wtt_load('widgets', 'iam', 'kms', 'auth');

-- validate the setup data
select is(count(*), 1::bigint) from auth_oidc_account where public_id = 'aoa___walter';
select is(count(*), 1::bigint) from auth_account where public_id = 'aoa___walter';

-- validate the insert triggers
prepare insert_oidc_account as
    insert into auth_oidc_account
    (auth_method_id,     public_id,    issuer, subject)
    values
        ('aom___widget',   'aoa___tania', 'https://widget.test', 'tania');
select lives_ok('insert_oidc_account');

select is(count(*), 1::bigint) from auth_oidc_account where public_id = 'aoa___tania';
select is(count(*), 1::bigint) from auth_account where public_id = 'aoa___tania';

-- validate the delete triggers
prepare delete_oidc_account as
    delete
    from auth_oidc_account
    where public_id = 'aoa___tania';
select lives_ok('delete_oidc_account');

select is(count(*), 0::bigint) from auth_oidc_account where public_id = 'aoa___tania';
select is(count(*), 0::bigint) from auth_account where public_id = 'aoa___tania';

select * from finish();
rollback;
