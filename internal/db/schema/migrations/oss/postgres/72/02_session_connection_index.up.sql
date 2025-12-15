-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create index if not exists session_connection_worker_id_closed_reason_ix
    on session_connection (worker_id, closed_reason);

commit;
