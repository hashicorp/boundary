begin;

-- Insert the global token
insert into app_token_global (
  public_id,
  scope_id,
  name,
  description,
  created_by_user_id,
  expiration_time
)
values (
  'at_global_children_per_org',
  'global',
  'Global Token - Children Per Org',
  'Token with one children permission per org and individual project grants',
  'u_recovery',
  now() + interval '1 year'
);

insert into app_token_cipher (
  app_token_id,
  key_id,
  token
)
values (
  'at_global_children_per_org',
  'kms_key_id_global',
  decode('636869326472656e5f7065725f6f7267', 'hex')
);

-- Create one permission per org with children grant scope
with org_permission_data as (
  select 
    'atpg_children_org_' || replace(public_id, 'o_', '') as private_id,
    'at_global_children_per_org' as app_token_id,
    'Children permission for org ' || public_id as description,
    true as grant_this_scope,
    'children' as grant_scope,
    public_id as org_id
  from iam_scope
  where type = 'org'
)
insert into app_token_permission_global (
  private_id,
  app_token_id,
  description,
  grant_this_scope,
  grant_scope
)
select 
  private_id,
  app_token_id,
  description,
  grant_this_scope,
  grant_scope
from org_permission_data;

-- Add grants to all permissions (ids=*;type=*;actions=*)
insert into app_token_permission_grant (
  permission_id,
  canonical_grant,
  raw_grant
)
select 
  'atpg_children_org_' || replace(public_id, 'o_', ''),
  'ids=*;type=*;actions=*',
  'ids=*;type=*;actions=*'
from iam_scope
where type = 'org';

-- Grant all projects under each org individually
-- This creates individual project grant scopes for each permission
insert into app_token_permission_global_individual_project_grant_scope (
  permission_id,
  scope_id,
  grant_scope
)
select 
  'atpg_children_org_' || replace(org_scope.public_id, 'o_', ''),
  project_scope.public_id,
  'children'
from iam_scope org_scope
join iam_scope project_scope 
  on project_scope.parent_id = org_scope.public_id
where org_scope.type = 'org' 
  and project_scope.type = 'project';

commit;