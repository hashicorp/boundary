-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- auth_token_status_enm entries define the possible auth token
-- states. 
create table auth_token_status_enm (
  name text primary key
    constraint name_only_predefined_auth_token_states_allowed
    check (
        name in ('auth token pending','token issued', 'authentication failed', 'system error')
    )
);

-- populate the values of auth_token_status_enm
insert into auth_token_status_enm(name)
  values
    ('auth token pending'),
    ('token issued'),
    ('authentication failed'),
    ('system error'); 


-- add the state column with a default to the auth_token table.
alter table auth_token
add column status text not null default 'token issued' -- safest default
references auth_token_status_enm(name)
  on update cascade
  on delete restrict;


create or replace view auth_token_account as
      select at.public_id,
              at.token,
              at.auth_account_id,
              at.create_time,
              at.update_time,
              at.approximate_last_access_time,
              at.expiration_time,
              aa.scope_id,
              aa.iam_user_id,
              aa.auth_method_id,
              at.status
        from auth_token as at
  inner join auth_account as aa
          on at.auth_account_id = aa.public_id;

commit;
