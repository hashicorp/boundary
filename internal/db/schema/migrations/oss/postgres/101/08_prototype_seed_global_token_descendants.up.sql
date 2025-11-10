begin;

-- Insert a single global token with descendants permission
insert into app_token_global (
  public_id,
  scope_id,
  name,
  description,
  created_by_user_id,
  expiration_time
)
values (
  'at_global_descendants',
  'global',
  'Global Token - Descendants',
  'Token with descendants permission for all orgs and projects',
  'u_recovery',
  now() + interval '1 year'
);

insert into app_token_cipher (
  app_token_id,
  key_id,
  token
)
values (
  'at_global_descendants',
  'kms_key_id_global',
  decode('64657363656e64616e74735f746f6b656e', 'hex')
);


-- Create individual permissions for each resource type with descendants grant scope
with resource_types as (
  select unnest(array[
    'alias',
    'auth-method', 
    'auth-token',
    'account',
    'billing',
    'controller',
    'credential',
    'credential-library',
    'credential-store',
    'group',
    'host',
    'host-catalog',
    'host-set',
    'managed-group',
    'policy',
    'role',
    'scope',
    'session',
    'session-recording',
    'storage-bucket',
    'target',
    'user',
    'worker'
  ]) as resource_type
)
insert into app_token_permission_global (
  private_id,
  app_token_id,
  description,
  grant_this_scope,
  grant_scope
)
select 
  'atpg_desc_' || replace(resource_type, '-', '_') as private_id,
  'at_global_descendants' as app_token_id,
  'Descendants permission for ' || resource_type || ' resources' as description,
  true as grant_this_scope,
  'descendants' as grant_scope
from resource_types;

-- Add grants for each permission with type-specific grants
with resource_types as (
  select unnest(array[
    'alias',
    'auth-method', 
    'auth-token',
    'account',
    'billing',
    'controller',
    'credential',
    'credential-library',
    'credential-store',
    'group',
    'host',
    'host-catalog',
    'host-set',
    'managed-group',
    'policy',
    'role',
    'scope',
    'session',
    'session-recording',
    'storage-bucket',
    'target',
    'user',
    'worker'
  ]) as resource_type
)
insert into app_token_permission_grant (
  permission_id,
  canonical_grant,
  raw_grant
)
select 
  'atpg_desc_' || replace(resource_type, '-', '_') as permission_id,
  'ids=*;type=' || resource_type || ';actions=*' as canonical_grant,
  'ids=*;type=' || resource_type || ';actions=*' as raw_grant
from resource_types;

commit;