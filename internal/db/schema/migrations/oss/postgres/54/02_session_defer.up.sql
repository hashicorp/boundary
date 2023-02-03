-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  alter table session alter constraint target_fkey                deferrable initially deferred;
  alter table session alter constraint session_auth_token_id_fkey deferrable initially deferred;
  alter table session alter constraint iam_scope_project_fkey     deferrable initially deferred;
  alter table session alter constraint session_host_id_fkey       deferrable initially deferred;
  alter table session alter constraint session_host_set_id_fkey   deferrable initially deferred;
  alter table session alter constraint session_user_id_fkey       deferrable initially deferred;
end;
