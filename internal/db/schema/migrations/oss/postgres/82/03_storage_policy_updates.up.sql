-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table policy_storage_policy_deleted (
    public_id wt_public_id primary key,
    delete_time wt_timestamp not null
  );
  comment on table policy_storage_policy_deleted is
    'policy_storage_policy_deleted holds the ID and delete_time of every deleted storage policy. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create trigger insert_deleted_id after delete on policy_storage_policy
    for each row execute function insert_deleted_id('policy_storage_policy_deleted');

  create index policy_storage_policy_deleted_delete_time_idx on policy_storage_policy_deleted (delete_time);

  -- Add new indexes for the create time and update time queries.
  create index policy_storage_policy_create_time_public_id_idx
      on policy_storage_policy (create_time desc, public_id desc);
  create index policy_storage_policy_update_time_public_id_idx
      on policy_storage_policy (update_time desc, public_id desc);

  analyze policy_storage_policy;

commit;
