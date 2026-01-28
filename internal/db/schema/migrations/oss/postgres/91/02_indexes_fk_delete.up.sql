-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- Index to help when setting target_id to null on a session
  -- when the corresponding target is deleted.
  drop index if exists session_target_id_ix;
  create index session_target_id_ix
            on session (target_id);

  -- Index to help when setting auth_token_id to null on a session
  -- when the corresponding auth_token is deleted.
  drop index if exists session_auth_token_id_ix;
  create index session_auth_token_id_ix
            on session (auth_token_id);

  -- Index to help when setting session_id to null on a credential_vault_credential
  -- when the corresponding session is deleted.
  drop index if exists credential_vault_credential_session_id_ix;
  create index credential_vault_credential_session_id_ix
            on credential_vault_credential (session_id);

  -- Index to help delete cascade of session_worker_protocol
  -- when the corresponding session is deleted.
  drop index if exists session_worker_protocol_session_id_ix;
  create index session_worker_protocol_session_id_ix
            on session_worker_protocol (session_id);

  -- Index to help when setting session_id to null on recording_connection
  -- when the corresponding session is deleted.
  drop index if exists recording_connection_session_id_ix;
  create index recording_connection_session_id_ix
            on recording_connection (session_id);

  -- Index to help delete of terminated sessions.
  drop index if exists session_state_state_start_time_ix;
  create index session_state_state_terminated_start_time_ix
            on session_state (state, start_time)
         where state = 'terminated';

  analyze session,
          credential_vault_credential,
          session_worker_protocol,
          recording_connection,
          session_state;
commit;
