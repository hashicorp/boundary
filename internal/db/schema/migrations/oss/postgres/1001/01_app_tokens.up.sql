-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table app_token (
  public_id wt_public_id primary key,
  create_time wt_timestamp not null,
  expiration_time wt_timestamp not null
    constraint expiration_time_not_greater_than_3_yrs
    check(
      expiration_time >= create_time and
      expiration_time <= create_time + interval '3 years'
    ),
  name text,
  description text,
  created_by wt_url_safe_id
    constraint iam_user_hst_key_fkey
    references iam_user_hst(history_id)
    on delete restrict -- History records with an app token cannot be deleted
    on update cascade,
  scope_id wt_scope_id not null
    constraint scope_id_key_fkey
    references iam_scope(public_id)
    on delete cascade
    on update cascade
);
comment on table app_token is
  'app_token defines an application auth token';

create or replace function app_token_immutable() returns trigger
  as $$
  begin
    raise exception 'app tokens are immutable';
  end;
$$ language plpgsql;

create trigger immutable_app_token before update on app_token
  for each row execute procedure app_token_immutable();

create table app_token_periodic_expiration_interval (
  app_token_id wt_public_id primary key
  constraint app_token_id_key_fkey
    references app_token(public_id)
    on delete cascade
    on update cascade,
  expiration_interval_in_max_seconds int not null
    constraint expiration_interval_in_max_seconds_must_be_greater_than_0
    check(expiration_interval_in_max_seconds > 0)
);
comment on table app_token is
  'app_token_periodic_expiration_interval defines the expiration interval for an application auth token';

create or replace function app_token_periodic_expiration_immutable() returns trigger
  as $$
  begin
    raise exception 'app token periodic expirations are immutable';
  end;
  $$ language plpgsql;

create trigger immutable_app_token_periodic_expiration before update on app_token
  for each row execute procedure app_token_periodic_expiration_immutable();

create table app_token_grant (
  create_time wt_timestamp not null,
  app_token_id wt_public_id -- pk
    constraint app_token_id_key_fkey
    references app_token(public_id)
    on delete cascade
    on update cascade,
  canonical_grant text -- pk
    constraint canonical_grant_must_not_be_empty
    check(
      length(trim(canonical_grant)) > 0
    ),
  raw_grant text not null
    constraint raw_grant_must_not_be_empty
    check(
      length(trim(raw_grant)) > 0
    ),
  primary key(app_token_id, canonical_grant)
);

create or replace function app_token_immutable_grant() returns trigger
  as $$
  begin
    raise exception 'app token grants are immutable';
  end;
$$ language plpgsql;

create trigger immutable_app_token_grant before update on app_token_grant
  for each row execute procedure app_token_immutable_grant();

commit;
