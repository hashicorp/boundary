begin;

-- Create one project token for each project
with project_token_data as (
  select 
    'at_proj_' || replace(public_id, 'p_', '') as public_id,
    public_id as scope_id,
    'Project Token for ' || public_id as name,
    'Token for project ' || public_id || ' with individual permissions' as description
  from iam_scope
  where type = 'project'
),
token_insert as (
  insert into app_token_project (
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
  from project_token_data
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
  decode('70726f6a5f746f6b656e5f' || encode(digest(public_id, 'sha256'), 'hex')::text, 'hex') as token
from project_token_data;



-- Create one permission per project token with individual grant scope
with project_permission_data as (
  select 
    'atpp_individual_' || replace(public_id, 'p_', '') as private_id,
    'at_proj_' || replace(public_id, 'p_', '') as app_token_id,
    'Individual permission for project ' || public_id as description,
    true as grant_this_scope,
    public_id as project_scope_id
  from iam_scope
  where type = 'project'
)
insert into app_token_permission_project (
  private_id,
  app_token_id,
  description,
  grant_this_scope
)
select 
  private_id,
  app_token_id,
  description,
  grant_this_scope
from project_permission_data;

-- Add grants to all project permissions
insert into app_token_permission_grant (
  permission_id,
  canonical_grant,
  raw_grant
)
select 
  'atpp_individual_' || replace(public_id, 'p_', ''),
  'ids=*;type=*;actions=*',
  'ids=*;type=*;actions=*'
from iam_scope
where type = 'project';

-- Grant the project itself to each project token
commit;