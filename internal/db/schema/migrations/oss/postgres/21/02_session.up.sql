-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

alter table session_connection
  -- intentionally null because we don't know the user_client_ip when the
  -- session is created by the controller.  The worker will update the session
  -- with the user_client_ip after the user establishes a connection.
  add column user_client_ip inet; 

commit;