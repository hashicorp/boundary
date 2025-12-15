-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create function wh_auth_token_deleted(p_auth_token_id wt_public_id) returns void
  as $$
  begin
    update wh_auth_token_accumulating_fact
       set auth_token_deleted_date_key = wh_date_key(now()),
           auth_token_deleted_time_key = wh_time_key(now()),
           auth_token_deleted_time     = now(),
           auth_token_valid_time_range = tstzrange(lower(auth_token_valid_time_range), now(), '[]')
     where auth_token_id = p_auth_token_id;
    return;
  end;
  $$ language plpgsql;
  comment on function wh_auth_token_deleted is
    'wh_auth_token_deleted is a function that updates the wh_auth_token_accumulating_fact'
    'when a previously issued auth_token is deleted.';

  create function auth_token_deleted() returns trigger
  as $$
  begin
    if old.status = 'token issued' then
      perform wh_auth_token_deleted(old.public_id);
    end if;
    return null;
  end;
  $$ language plpgsql;

  create trigger auth_token_deleted after delete on auth_token
    for each row execute procedure auth_token_deleted();
commit;
