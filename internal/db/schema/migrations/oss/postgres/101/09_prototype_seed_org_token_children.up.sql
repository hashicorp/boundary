begin;
-- Insert 1000 additional test org tokens with grants
with test_token_data as (
  select 
    'at_org_' || lpad(generate_series::text, 4, '0') as public_id,
    'o__________' || ((generate_series % 30) + 1) as scope_id,
    'Org Test Token #' || generate_series as name,
    'Test token with children permissions for projects #' || generate_series as description,
    'u_recovery' as created_by_user_id,
    'kms_key_id_global' as key_id,
    decode('746573745f746f6b656e5f6279746573' || lpad(to_hex(generate_series), 8, '0'), 'hex') as token
  from generate_series(1, 1000)
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
    created_by_user_id,
    now() + interval '1 year'
  from test_token_data
  returning public_id
)
insert into app_token_cipher (
  app_token_id,
  key_id,
  token
)
select 
  public_id,
  key_id,
  token
from test_token_data;


-- Create permissions for the 1000 test org tokens
with test_permission_data as (
  select 
    'atpo_children_' || lpad(generate_series::text, 4, '0') as private_id,
    'at_org_' || lpad(generate_series::text, 4, '0') as app_token_id,
    'children permissions for projects #' || generate_series as description,
    true as grant_this_scope,
    'children' as grant_scope
  from generate_series(1, 1000)
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
from test_permission_data;

-- Add grants to all 1000 test org permissions
insert into app_token_permission_grant (
  permission_id,
  canonical_grant,
  raw_grant
)
select 
  'atpo_children_' || lpad(generate_series::text, 4, '0'),
  'type=*;action=*',
  'type=*;action=*'
from generate_series(1, 1000);

commit;
