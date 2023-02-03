-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

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
