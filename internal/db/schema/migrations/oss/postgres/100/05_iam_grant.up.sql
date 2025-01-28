-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- iam_grant is the root table for a grant value object.
  -- A grant can only reference a single resource, including the special
  -- strings "*" to indicate "all" resources, and "unknown" when no resource is set.
  create table iam_grant (
    canonical_grant text not null primary key,
    resource text not null
      constraint resource_enm_fkey
        references resource_enm(string)
        on delete restrict
        on update cascade
  );

  create index iam_grant_resource_ix
    on iam_grant (resource);

  create function set_resource() returns trigger
  as $$
  declare resource text[];
  begin
    select regexp_matches(new.canonical_grant, 'type=([^;]+);')
    into resource;
    if resource is null then
      new.resource = 'unknown';
    else
      new.resource = resource[1];
    end if;
    return new;
  end
  $$ language plpgsql;

  create trigger set_resource before insert on iam_grant
    for each row execute procedure set_resource();

commit;