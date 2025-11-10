begin;

-- Create one org token for each organization
with org_token_data as (
  select 
    'at_org_' || replace(public_id, 'o_', '') as public_id,
    public_id as scope_id,
    'Org Token for ' || public_id as name,
    'Token for org ' || public_id || ' with individual project grants' as description
  from iam_scope
  where type = 'org'
),
token_insert as (
  insert into app_token_org (
    public_id,
    scope_id,
    name,
    description,
    created_by_user_id,
    expiration_time
  )
  select 
    public_id,
    scope_id,
    name,
    description,
    'u_recovery' as created_by_user_id,
    now() + interval '1 year' as expiration_time
  from org_token_data
  returning public_id
)
insert into app_token_cipher (
  app_token_id,
  key_id,
  token
)
select 
  public_id,
  'kms_key_id_global' as key_id,
  decode('6f72675f746f6b656e5f' || encode(digest(public_id, 'sha256'), 'hex')::text, 'hex') as token
from org_token_data;


-- Create one permission per org token with individual grant scope
with org_permission_data as (
  select 
    'atpo_individual_' || replace(public_id, 'o_', '') as private_id,
    'at_org_' || replace(public_id, 'o_', '') as app_token_id,
    'Individual permission for org ' || public_id as description,
    true as grant_this_scope,
    'individual' as grant_scope,
    public_id as org_scope_id
  from iam_scope
  where type = 'org'
)
insert into app_token_permission_org (
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

-- Add grants to all org permissions
insert into app_token_permission_grant (
  permission_id,
  canonical_grant,
  raw_grant
)
select 
  'atpo_individual_' || replace(public_id, 'o_', ''),
  'ids=*;type=*;actions=*',
  'ids=*;type=*;actions=*'
from iam_scope
where type = 'org';

-- Grant all projects under each org individually
insert into app_token_permission_org_individual_grant_scope (
  permission_id,
  scope_id,
  grant_scope
)
select 
  'atpo_individual_' || replace(org_scope.public_id, 'o_', '') as permission_id,
  project_scope.public_id as scope_id,
  'individual' as grant_scope
from iam_scope org_scope
join iam_scope project_scope 
  on project_scope.parent_id = org_scope.public_id
where org_scope.type = 'org' 
  and project_scope.type = 'project';

commit;