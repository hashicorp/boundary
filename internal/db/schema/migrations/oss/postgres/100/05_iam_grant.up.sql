-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- wt_canonical_grant domain represents Boundary canonical grant.
  -- A canonical grant is a semicolon-separated list of key=value pairs.
  -- e.g. "ids=*;type=role;actions=read;output_fields=id,name"
  create domain wt_canonical_grant as text
    check(
      value ~ '^(?:[^;=]+=[^;=]+)(?:;[^;=]+=[^;=]+)*?$'
    );
  comment on domain wt_canonical_grant is
    'A canonical grant is a semicolon-separated list of key=value pairs.';

  -- iam_grant is the root table for a grant value object.
  -- A grant can only reference a single resource, including the special
  -- strings "*" to indicate "all" resources, and "unknown" when no resource is set.
  create table iam_grant (
    canonical_grant wt_canonical_grant primary key,
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

  -- set_resource sets the resource column based on the "type" token in the canonical_grant.
  create function set_resource() returns trigger
  as $$
  declare type_matches text[];
  begin
    -- Extract all "type" tokens from the canonical_grant string
    with
    parts (p) as (
      select p
        from regexp_split_to_table(new.canonical_grant, ';') as p
    ),
    kv (k, v) as (
    select part[1] as k,
      part[2] as v
    from parts,
      regexp_split_to_array(parts.p, '=') as part
    )
    select array_agg(v)
      into type_matches
    from kv
    where k = 'type';

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
    'set_resource sets the resource column based on the "type" token. A valid grant without a type token results in resource being set to "unknown".';

  create trigger set_resource before insert on iam_grant
    for each row execute procedure set_resource();

  -- migrate existing canonical_grant values from iam_role_grant to iam_grant
  insert into iam_grant
    (canonical_grant)
  select distinct canonical_grant
    from iam_role_grant;
  
  -- alter iam_grant canonical_grant column to add a check constraint to ensure that the canonical_grant is valid.
  alter table iam_grant
    add constraint canonical_grant_is_valid
      check (
        canonical_grant ~ '^(?:[^;=]+=[^;=]+)(?:;[^;=]+=[^;=]+)*?$'
      );

  -- Add a foreign key constraint to the iam_role_grant table to ensure that the canonical_grant exists in the iam_grant table.
  -- Alter to add foreign key constraint to the iam_role_grant table defined in 01/06_iam.up.sql
  alter table iam_role_grant
    add constraint iam_grant_fkey
     foreign key (canonical_grant)
        references iam_grant(canonical_grant)
        on delete cascade
        on update cascade;

commit;