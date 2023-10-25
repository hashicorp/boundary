-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;
select plan(12);
select wtt_load('widgets','iam','kms');

-- validate the app_token update trigger
prepare insert_app_token as
  insert into app_token
  (public_id, create_time,    expiration_time, scope_id, name, description, created_by)
  SELECT 'appt_____clare', now(), now() + interval '1 hour', 'o_____colors','test-app-token-name','test-description', iam_user_hst.history_id
  FROM iam_user_hst
  JOIN iam_user ON iam_user.public_id = iam_user_hst.public_id
  WHERE iam_user.public_id LIKE 'u______clare';
select lives_ok('insert_app_token');

select is(count(*), 1::bigint) from app_token where public_id = 'appt_____clare';

prepare update_app_token as
  update app_token set name = 'updated-name', public_id = 'appt_____tania' where  public_id = 'appt_____clare';

select throws_ok('update_app_token', 'app tokens are immutable');

-- validate app_token_periodic_expiration_interval triggers
prepare insert_app_token_periodic_expiration_interval_with_zero_secs as
  insert into app_token_periodic_expiration_interval
  (app_token_id, expiration_interval_in_max_seconds)
  values('appt_____clare', 0);
select throws_like('insert_app_token_periodic_expiration_interval_with_zero_secs', '%expiration_interval_in_max_seconds_must_be_greater_than_0%');

prepare insert_app_token_periodic_expiration_interval as
  insert into app_token_periodic_expiration_interval
  (app_token_id, expiration_interval_in_max_seconds)
  values('appt_____clare', 3600);
select lives_ok('insert_app_token_periodic_expiration_interval', '%expiration_interval_in_max_seconds_must_be_greater_than_0%');

select is(count(*), 1::bigint) from app_token_periodic_expiration_interval where app_token_id = 'appt_____clare';

prepare update_app_token_periodic_expiration_interval as
  update app_token_periodic_expiration_interval set expiration_interval_in_max_seconds = 60 where  app_token_id = 'appt_____clare';

select throws_ok('update_app_token_periodic_expiration_interval', 'app token periodic expirations are immutable');

-- validate app_token_grant triggers
prepare insert_app_token_grant as
  insert into app_token_grant
  (app_token_id, create_time, canonical_grant, raw_grant)
  values('appt_____clare', now(), 'test-canonical-grant', 'test-raw-grant');
select lives_ok('insert_app_token_grant');

select is(count(*), 1::bigint) from app_token_grant where app_token_id = 'appt_____clare' AND canonical_grant = 'test-canonical-grant';

prepare update_app_token_grant as
  update app_token_grant set create_time = now() + interval '1 hour' where  app_token_id = 'appt_____clare';

select throws_ok('update_app_token_grant', 'app token grants are immutable');

-- validate app_token_usage triggers
prepare insert_app_token_usage as
  insert into app_token_usage
  (app_token_id, create_time, client_tcp_address, request_method, request_path)
  values('appt_____clare', now(), '192.168.0.1', 'cli', 'test-request-path');
select lives_ok('insert_app_token_usage');

select is(count(*), 1::bigint) from app_token_grant where app_token_id = 'appt_____clare' AND canonical_grant = 'test-canonical-grant';

rollback;