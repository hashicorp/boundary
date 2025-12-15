-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Modify the wt_alias domain to include explicit casts in its constraints
alter domain wt_alias drop constraint if exists wt_alias_too_short;
alter domain wt_alias drop constraint if exists wt_alias_no_suround_spaces;

alter domain wt_alias add constraint wt_alias_too_short
  check (length(trim(both from value::text)) > 0);
alter domain wt_alias add constraint wt_alias_no_suround_spaces
  check (trim(both from value::text) = value::text);

-- Modify the wt_target_alias domain to include explicit casts in its constraints
alter domain wt_target_alias drop constraint if exists wt_target_alias_too_long;

alter domain wt_target_alias add constraint wt_target_alias_too_long
  check (length(trim(both from value::text)) < 254);

commit;