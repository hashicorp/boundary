begin;

CREATE TABLE if not exists oplog_entry (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  version text NOT NULL,
  aggregate_name text NOT NULL,
  "data" bytea NOT NULL
);
CREATE TABLE if not exists oplog_ticket (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  update_time wt_timestamp,
  "name" text NOT NULL UNIQUE,
  "version" bigint NOT NULL
);
CREATE TABLE if not exists oplog_metadata (
  id bigint generated always as identity primary key,
  create_time wt_timestamp,
  entry_id bigint NOT NULL REFERENCES oplog_entry(id) ON DELETE CASCADE ON UPDATE CASCADE,
  "key" text NOT NULL,
  value text NULL
);
create index if not exists idx_oplog_metatadata_key on oplog_metadata(key);
create index if not exists idx_oplog_metatadata_value on oplog_metadata(value);
INSERT INTO oplog_ticket (name, version)
values
  ('default', 1),
  ('iam_scope', 1),
  ('iam_user', 1),
  ('iam_auth_method', 1),
  ('iam_group', 1),
  ('iam_group_member_user', 1),
  ('iam_role', 1),
  ('iam_role_grant', 1),
  ('iam_role_group', 1),
  ('iam_role_user', 1),
  ('db_test_user', 1),
  ('db_test_car', 1),
  ('db_test_rental', 1),
  ('kms_key_entry', 1);

commit;
