-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create function wh_auth_token_issued(p_auth_token_id wt_public_id, issued_ts wt_timestamp, last_accessed_ts wt_timestamp) returns void
  as $$
  declare
    new_row wh_auth_token_accumulating_fact%rowtype;
  begin
    insert into wh_auth_token_accumulating_fact (
                auth_token_id,
                user_key,
                auth_token_issued_date_key,
                auth_token_issued_time_key,
                auth_token_issued_time,
                auth_token_approximate_last_access_date_key,
                auth_token_approximate_last_access_time_key,
                auth_token_approximate_last_access_time,
                auth_token_approximate_active_time_range,
                auth_token_valid_time_range
    )
         select p_auth_token_id,
                wh_upsert_user(p_auth_token_id),
                wh_date_key(issued_ts),
                wh_time_key(issued_ts),
                issued_ts,
                wh_date_key(last_accessed_ts),
                wh_time_key(last_accessed_ts),
                last_accessed_ts,
                tstzrange(issued_ts, last_accessed_ts,         '[]'),
                tstzrange(issued_ts, 'infinity'::wt_timestamp, '[]')
      returning * into strict new_row;
    return;
  end;
  $$ language plpgsql;
  comment on function wh_auth_token_issued is
    'wh_auth_token_issued is a function called when an auth token is issued to insert a fact into the auth token accumulating fact table.';

  create function auth_token_inserted() returns trigger
  as $$
  begin
    if new.status = 'token issued' then
      perform wh_auth_token_issued(new.public_id, new.update_time, new.approximate_last_access_time);
    end if;
    return null;
  end;
  $$ language plpgsql;

  create trigger auth_token_inserted after insert on auth_token
    for each row execute procedure auth_token_inserted();
commit;
