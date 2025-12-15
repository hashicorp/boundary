-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Remove immutable property
drop trigger immutable_role_grant on iam_role_grant;

-- Swap add-host-sets to add-host-sources
update iam_role_grant
set
  canonical_grant = replace(
    canonical_grant,
    'add-host-sets',
    'add-host-sources'
  );

update iam_role_grant
set
  raw_grant = replace(
    raw_grant,
    'add-host-sets',
    'add-host-sources'
  );

-- Swap set-host-sets to set-host-sources
update iam_role_grant
set
  canonical_grant = replace(
    canonical_grant,
    'set-host-sets',
    'set-host-sources'
  );

update iam_role_grant
set
  raw_grant = replace(
    raw_grant,
    'set-host-sets',
    'set-host-sources'
  );

-- Swap remove-host-sets to remove-host-sources
update iam_role_grant
set
  canonical_grant = replace(
    canonical_grant,
    'remove-host-sets',
    'remove-host-sources'
  );

update iam_role_grant
set
  raw_grant = replace(
    raw_grant,
    'remove-host-sets',
    'remove-host-sources'
  );

-- Swap add-credential-libraries to add-credential-sources
update iam_role_grant
set
  canonical_grant = replace(
    canonical_grant,
    'add-credential-libraries',
    'add-credential-sources'
  );

update iam_role_grant
set
  raw_grant = replace(
    raw_grant,
    'add-credential-libraries',
    'add-credential-sources'
  );

-- Swap set-credential-libraries to set-credential-sources
update iam_role_grant
set
  canonical_grant = replace(
    canonical_grant,
    'set-credential-libraries',
    'set-credential-sources'
  );

update iam_role_grant
set
  raw_grant = replace(
    raw_grant,
    'set-credential-libraries',
    'set-credential-sources'
  );

-- Swap remove-credential-libraries to remove-credential-sources
update iam_role_grant
set
  canonical_grant = replace(
    canonical_grant,
    'remove-credential-libraries',
    'remove-credential-sources'
  );

update iam_role_grant
set
  raw_grant = replace(
    raw_grant,
    'remove-credential-libraries',
    'remove-credential-sources'
  );

create trigger immutable_role_grant before update on iam_role_grant
  for each row execute procedure iam_immutable_role_grant();

commit;