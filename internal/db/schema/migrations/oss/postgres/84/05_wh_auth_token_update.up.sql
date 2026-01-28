-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create function wh_auth_token_accessed(p_auth_token_id wt_public_id, last_accessed_ts wt_timestamp) returns void
  as $$
  begin
    update wh_auth_token_accumulating_fact
       set auth_token_approximate_last_access_date_key = wh_date_key(last_accessed_ts),
           auth_token_approximate_last_access_time_key = wh_time_key(last_accessed_ts),
           auth_token_approximate_last_access_time     = last_accessed_ts,
           auth_token_approximate_active_time_range    = tstzrange(lower(auth_token_approximate_active_time_range), last_accessed_ts, '[]')
     where auth_token_id = p_auth_token_id;
    return;
  end;
  $$ language plpgsql;
  comment on function wh_auth_token_accessed is
    'wh_auth_token_accessed is a function that updates the wh_auth_token_accumulating_fact'
    'when an auth_token is accessed.';

  create function auth_token_updated() returns trigger
  as $$
  begin
    case
      when new.status = 'token issued' and new.status is distinct from old.status then
        perform wh_auth_token_issued(new.public_id, new.update_time, new.approximate_last_access_time);
      when new.approximate_last_access_time is distinct from old.approximate_last_access_time then
        perform wh_auth_token_accessed(new.public_id, new.approximate_last_access_time);
      else
        return null;
    end case;
    return null;
  end;
  $$ language plpgsql;

  create trigger auth_token_updated after update on auth_token
    for each row execute procedure auth_token_updated();
commit;
