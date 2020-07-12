/*
  Given a user ID, find all grants from all roles containing:
    #1 `global:u_anon` in users;
    #2 `global:u_auth` in users;
    #3 the user ID itself in users (note that the principals are stored with the user scope, not role scope, after #177 lands), and
    #4 a group containing the user
  Given no user ID, find all grants from all roles containing `global:u_anon`
  In both cases, what needs to be returned is a set of tuples of `(scope_id,` grant).
  The `scope_id` should match the `grant_scope_id` parameter from the role in which the grant was sourced.

  find all canonical grant strings plus the grant scope id
  for all roles
  where the user id is assigned to the role
    or the user id is assigned to a group that is assigned to the role
    or the anonymous user or authenticated user is assigned to the role
    or the anonymous user or authenticated user is assigned to a group that is assigned to the role
*/

with
users (id) as (
  select public_id
    from iam_user
   -- where clauses for testing
   -- where public_id in ('u_anon')
   -- where public_id in ('u_auth')
   -- where public_id in ('u_anon', 'u_auth')

   -- run against sample database
   -- where public_id in ('u______nancy') -- Nancy has no direct or indirect grants
   -- where public_id in ('u______cindy') -- Cindy has some
   -- where public_id in ('u_anon', 'u_auth', 'u______nancy')
   -- where public_id in ('u_anon', 'u_auth', 'u______cindy')

   -- use this where clause in the code for an authenticated user
   where public_id in ('u_anon', 'u_auth', ?)
   -- use this where clause in the code for an unauthenticated
   -- where public_id in ('u_anon')
),
user_groups (id) as (
  select group_id
    from iam_group_member_user,
         users
   where member_id in (users.id)
),
group_roles (role_id) as (
  select role_id
    from iam_group_role,
         user_groups
   where principal_id in (user_groups.id)
),
user_roles (role_id) as (
  select role_id
    from iam_user_role,
         users
   where principal_id in (users.id)
),
user_group_roles (role_id) as (
  select role_id
    from group_roles
   union
  select role_id
    from user_roles
),
roles (role_id, grant_scope_id) as (
  select iam_role.public_id,
         iam_role.grant_scope_id
    from iam_role,
         user_group_roles
   where public_id in (user_group_roles.role_id)
),
final (role_scope, role_grant) as (
  select roles.grant_scope_id,
         iam_role_grant.canonical_grant
    from roles
   inner
    join iam_role_grant
      on roles.role_id = iam_role_grant.role_id
)
select role_scope, role_grant from final;
