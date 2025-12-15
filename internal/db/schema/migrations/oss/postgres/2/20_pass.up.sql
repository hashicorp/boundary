-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- auth_password_method_with_is_primary is useful for reading a password auth
-- method with a bool to determine if it's the scope's primary auth method.
create view auth_password_method_with_is_primary as 
select 
  case when s.primary_auth_method_id is not null then
    true
  else false end
  as is_primary_auth_method,    
  am.public_id,
  am.scope_id,
  am.password_conf_id,
  am.name,
  am.description,
  am.create_time,
  am.update_time,
  am.version,
  am.min_login_name_length,
  am.min_password_length
from 
  auth_password_method am
  left outer join iam_scope s on am.public_id = s.primary_auth_method_id;
comment on view auth_password_method_with_is_primary is
  'password auth method with an is_primary_auth_method bool';


commit;
