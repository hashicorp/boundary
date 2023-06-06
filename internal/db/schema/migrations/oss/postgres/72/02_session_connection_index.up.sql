-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

  create index if not exists session_connection_worker_id_closed_reason_ix
    on session_connection (worker_id, closed_reason);

commit;
