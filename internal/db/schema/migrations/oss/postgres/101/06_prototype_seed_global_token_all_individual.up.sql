begin;

-- Create one global app token with individual permissions for every org and project in the system

-- First, insert the global token
insert into app_token_global (
  public_id,
  scope_id,
  created_by_user_id,
  name,
  description,
  expiration_time
)
values (
  'at_global_comprehensive',
  'global',
  'u_recovery',
  'Comprehensive Global Token',
  'Token with individual permissions for every org and project',
  now() + interval '1 year'
);

insert into app_token_cipher (
  app_token_id,
  key_id,
  token
)
values (
  'at_global_comprehensive',
  'kms_key_id_global',
  decode('deadbeefcafebabe0123456789abcdef', 'hex')
);


-- Then insert permissions for each org and project
with 
-- Get all orgs and projects from the system
all_scopes as (
  select public_id as scope_id, 'org' as scope_type
    from iam_scope 
   where type = 'org'
  union all
  select public_id as scope_id, 'project' as scope_type
    from iam_scope 
   where type = 'project'
),
-- Create permission IDs for each scope
permission_data as (
  select 
    'atpg_comprehensive_' || row_number() over (order by scope_id) as private_id,
    'at_global_comprehensive' as app_token_id,
    'individual' as grant_scope,
    'Individual permission for ' || scope_type || ' ' || scope_id as description,
    true as grant_this_scope,
    scope_id,
    scope_type
  from all_scopes
),
-- Insert permissions
permission_insert as (
  insert into app_token_permission_global (
    private_id,
    app_token_id,
    grant_scope,
    description,
    grant_this_scope
  )
  select 
    private_id,
    app_token_id,
    grant_scope,
    description,
    grant_this_scope
  from permission_data
  returning private_id, app_token_id, grant_scope, grant_this_scope
)
-- Insert grants for all permissions - one for each resource type
insert into app_token_permission_grant (
  permission_id,
  canonical_grant,
  raw_grant
)
select 
  pd.private_id,
  'ids=*;type=' || resource_types.type_name || ';actions=*',
  'ids=*;type=' || resource_types.type_name || ';actions=*'
from permission_data pd
cross join (
  values 
    ('alias'),
    ('auth-method'),
    ('auth-token'),
    ('account'),
    ('billing'),
    ('controller'),
    ('credential'),
    ('credential-library'),
    ('credential-store'),
    ('group'),
    ('host'),
    ('host-catalog'),
    ('host-set'),
    ('managed-group'),
    ('policy'),
    ('role'),
    ('scope'),
    ('session'),
    ('session-recording'),
    ('storage-bucket'),
    ('target'),
    ('user'),
    ('worker')
) as resource_types(type_name);

-- Insert individual org grant scopes
insert into app_token_permission_global_individual_org_grant_scope (
  permission_id,
  scope_id,
  grant_scope
)
with all_scopes as (
  select public_id as scope_id, 'org' as scope_type
    from iam_scope 
   where type = 'org'
  union all
  select public_id as scope_id, 'project' as scope_type
    from iam_scope 
   where type = 'project'
),
permission_data as (
  select 
    'atpg_comprehensive_' || row_number() over (order by scope_id) as private_id,
    scope_id,
    scope_type
  from all_scopes
)
select 
  pd.private_id,
  pd.scope_id,
  'individual'
from permission_data pd
where pd.scope_type = 'org';

-- Insert individual project grant scopes into the project-specific table
insert into app_token_permission_global_individual_project_grant_scope (
  permission_id,
  scope_id,
  grant_scope
)
with all_scopes as (
  select public_id as scope_id, 'org' as scope_type
    from iam_scope 
   where type = 'org'
  union all
  select public_id as scope_id, 'project' as scope_type
    from iam_scope 
   where type = 'project'
),
permission_data as (
  select 
    'atpg_comprehensive_' || row_number() over (order by scope_id) as private_id,
    scope_id,
    scope_type
  from all_scopes
)
select 
  pd.private_id,
  pd.scope_id,
  'individual'
from permission_data pd
where pd.scope_type = 'project';


commit;