-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  alter table session alter constraint target_fkey                deferrable initially deferred;
  alter table session alter constraint session_auth_token_id_fkey deferrable initially deferred;
  alter table session alter constraint iam_scope_project_fkey     deferrable initially deferred;
  alter table session alter constraint session_host_id_fkey       deferrable initially deferred;
  alter table session alter constraint session_host_set_id_fkey   deferrable initially deferred;
  alter table session alter constraint session_user_id_fkey       deferrable initially deferred;
end;
