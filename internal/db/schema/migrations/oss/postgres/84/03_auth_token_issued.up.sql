-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  create function auth_token_before_issued() returns trigger
  as $$
  begin
    if new.status = 'token issued' then
      new.approximate_last_access_time = now();
    end if;
    return new;
  end;
  $$ language plpgsql;

  create trigger auth_token_before_inserted before insert on auth_token
    for each row execute procedure auth_token_before_issued();
  create trigger auth_token_before_updated before update on auth_token
    for each row execute procedure auth_token_before_issued();
commit;
