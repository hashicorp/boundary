-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Create the app_token_view to unify app tokens from different scopes
create or replace view app_token_view as
    select
        public_id,
        scope_id,
        name,
        description,
        approximate_last_access_time,
        create_time,
        update_time,
        revoked,
        expiration_time,
        time_to_stale_seconds,
        created_by_user_id
   from app_token_global
  union all
    select
        public_id,
        scope_id,
        name,
        description,
        approximate_last_access_time,
        create_time,
        update_time,
        revoked,
        expiration_time,
        time_to_stale_seconds,
        created_by_user_id
   from app_token_org
  union all
    select
        public_id,
        scope_id,
        name,
        description,
        approximate_last_access_time,
        create_time,
        update_time,
        revoked,
        expiration_time,
        time_to_stale_seconds,
        created_by_user_id
   from app_token_project;
    
comment on view app_token_view is
    'app_token_view is a unified view of all app tokens across global, org, and project scopes';

commit;