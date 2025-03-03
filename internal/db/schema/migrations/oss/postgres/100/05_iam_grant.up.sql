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

  create or replace function set_resource() returns trigger
  as $$
  declare type_matches text[];
  begin
    -- validate that every token is in the form key=value
    if not new.canonical_grant ~ '^(?:[^;=]+=[^;=]+)(?:;[^;=]+=[^;=]+)*;?$' then
      raise exception 'malformed grant: %', new.canonical_grant;
    end if;

    -- Extract all "type" tokens from the canonical_grant string
    select array_agg(t[1])
      into type_matches
    from regexp_matches(new.canonical_grant, '(?<=^|;)type=([^;]+)(?=;|$)', 'g') as t;

    -- if there are multiple canonical grant types specified, throw an error.
    -- Ensure that the canonical_grant type is only referencing a single resource
    if type_matches is not null and array_length(type_matches, 1) > 1 then
      raise exception 'multiple type tokens in grant. only one type expected: %', new.canonical_grant;
    elsif type_matches is not null and array_length(type_matches, 1) = 1 then
      new.resource := type_matches[1];
    else
      new.resource := 'unknown';
    end if;
    return new;
  end
  $$ language plpgsql;
  comment on function set_resource() is
    'set_resource is a trigger function that validates the canonical grant string and sets the resource column based on the "type" token. Malformed tokens raise an exception. A valid grant without a type token results in resource being set to "unknown".';

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