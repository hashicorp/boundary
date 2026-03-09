-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table server_worker_session_info_request (
  worker_id wt_public_id
  	constraint server_worker_fkey
    	references server_worker(public_id)
    	on delete cascade
    	on update cascade,
  last_request_time timestamp with time zone not null,
  primary key (worker_id)
);
comment on table server_worker_session_info_request is
  'server_worker_session_info_request is a table where each row represents the last request time a worker has reported its session information.';

commit;