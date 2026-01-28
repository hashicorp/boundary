-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;


-- the intent of this update statement: set the primary auth method for scopes
-- that only have a single auth_password_method, since currently there are only
-- auth_password_methods in boundary. Before this release all
-- auth_password_methods were "basically" primary auth methods and would create
-- an iam_user on first login.
with single_authmethod (scope_id, public_id) as (
  select 
    am.scope_id, 
    am.public_id  
  from 
    auth_password_method am,
    (select 
        scope_id, 
        count(public_id) as cnt 
     from 
        auth_password_method 
     group by scope_id) as singles
    where 
      am.scope_id = singles.scope_id and
      singles.cnt = 1
)
update 
  iam_scope
set 
  primary_auth_method_id = p.public_id
from
  single_authmethod p
where p.scope_id = iam_scope.public_id;


-- the intent of the insert with select statement: log the scopes that have more
-- than 1 auth method and therefore cannot have their primary auth method
-- automatically set for them.
with many_authmethod (scope_id, authmethod_cnt) as (
  select 
    am.scope_id, 
    many.cnt
  from 
    auth_password_method am,
    (select 
        scope_id, 
        count(public_id) as cnt 
     from 
        auth_password_method 
     group by scope_id) as many
    where 
      am.scope_id = many.scope_id and
      many.cnt > 1
)
insert into log_migration(entry, edition) 
select 
  distinct  concat(
      'unable to set primary_auth_method for ', 
      public_id,
      ' there were ', 
      m.authmethod_cnt, 
      ' password auth methods for that scope.'
  ) as entry, 'oss'
from
  iam_scope s,
  many_authmethod m
where 
  s.primary_auth_method_id is null and 
  s.public_id = m.scope_id;

commit;
