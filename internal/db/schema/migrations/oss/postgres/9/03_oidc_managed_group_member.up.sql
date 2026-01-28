-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Mappings of account to oidc managed groups. This is a non-abstract table with
-- a view (below) so that it is a natural aggregate for the oplog (also below).
create table auth_oidc_managed_group_member_account (
  create_time wt_timestamp,
  managed_group_id wt_public_id
    references auth_oidc_managed_group(public_id)
    on delete cascade
    on update cascade,
  member_id wt_public_id
    references auth_oidc_account(public_id)
    on delete cascade
    on update cascade,
  primary key (managed_group_id, member_id)
);
comment on table auth_oidc_managed_group_member_account is
'auth_oidc_managed_group_member_account is the join table for managed oidc groups and accounts.';

-- auth_immutable_managed_oidc_group_member_account() ensures that group members are immutable. 
create or replace function auth_immutable_managed_oidc_group_member_account() returns trigger
as $$
begin
    raise exception 'managed oidc group members are immutable';
end;
$$ language plpgsql;

create trigger default_create_time_column before insert on auth_oidc_managed_group_member_account
  for each row execute procedure default_create_time();

create trigger auth_immutable_managed_oidc_group_member_account before update on auth_oidc_managed_group_member_account
  for each row execute procedure auth_immutable_managed_oidc_group_member_account();

-- Updated in 64/01_ldap.up.sql
-- Initially create the view with just oidc; eventually we can replace this view
-- to union with other subtype tables.
create view auth_managed_group_member_account as
select
  oidc.create_time,
  oidc.managed_group_id,
  oidc.member_id
from
  auth_oidc_managed_group_member_account oidc;

commit;
