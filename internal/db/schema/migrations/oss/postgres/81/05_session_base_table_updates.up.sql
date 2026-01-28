-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Drop old list indexes that interfere with the new list requests.
  drop index session_create_time, session_list_pix;

  -- Add new indexes for the list queries. These indexes have been
  -- carefully tested to cover the different expected queries.
  create index session_project_id_create_time_list_idx
            on session (project_id,
                        create_time desc,
                        public_id   desc,
                        termination_reason);
  create index session_project_id_update_time_list_idx
            on session (project_id,
                        update_time desc,
                        public_id   desc,    
                        termination_reason);
  create index session_user_id_project_id_create_time_list_idx
            on session (user_id,
                        project_id,
                        create_time desc,
                        public_id   desc,
                        termination_reason);
  create index session_user_id_project_id_update_time_list_idx
            on session (user_id,
                        project_id,         
                        update_time desc,
                        public_id   desc,
                        termination_reason);

  analyze session;

commit;
