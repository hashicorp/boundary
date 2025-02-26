-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- iam_grant is the root table for a grant value object.
  -- A grant can only reference a single resource, including the special
  -- strings "*" to indicate "all" resources, and "unknown" when no resource is set.
  create table iam_grant (
    canonical_grant text primary key,
    resource text not null
      constraint iam_grant_resource_enm_fkey
        references iam_grant_resource_enm(name)
        on delete restrict
        on update cascade
  );
  comment on table iam_grant is
    'iam_grant is the root table for a grant value object. A grant can only reference a single resource, including the special strings "*" to indicate "all" resources, and "unknown" when no resource is set.';

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
  comment on function set_resource() is
    'set_resource is a trigger function that sets the resource column based on the canonical_grant.';

  create trigger set_resource before insert on iam_grant
    for each row execute procedure set_resource();

  -- Add a foreign key constraint to the iam_role_grant table to ensure that the canonical_grant exists in the iam_grant table.
  -- Alter to add foreign key constraint to the iam_role_grant table defined in 01/06_iam.up.sql
  alter table iam_role_grant
    add constraint iam_grant_fkey
     foreign key (canonical_grant)
        references iam_grant(canonical_grant)
        on delete cascade
        on update cascade;

commit;