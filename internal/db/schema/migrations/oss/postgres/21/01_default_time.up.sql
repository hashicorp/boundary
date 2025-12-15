-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Replaces function from 0/01_domain_types.up.sql
create or replace function default_create_time() returns trigger
as $$
begin
  if new.create_time is distinct from now() then
    new.create_time = now();
  end if;
  return new;
end;
$$ language plpgsql;

commit;
