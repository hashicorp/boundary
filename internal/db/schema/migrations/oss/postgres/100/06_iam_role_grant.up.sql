-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create index iam_role_grant_canonical_grant_ix
    on iam_role_grant (canonical_grant);

  create function upsert_canonical_grant() returns trigger
  as $$
  begin
    insert into iam_grant
      (canonical_grant)
    values
      (new.canonical_grant)
    on conflict do nothing;
    return new;
  end
  $$ language plpgsql;

  create trigger upsert_canonical_grant before insert on iam_role_grant
    for each row execute procedure upsert_canonical_grant();

commit;