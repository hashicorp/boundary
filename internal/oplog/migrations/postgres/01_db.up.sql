CREATE TABLE if not exists oplog_entry (
  id bigint generated always as identity primary key,
  created_at timestamp with time zone default current_timestamp,
  updated_at timestamp with time zone default current_timestamp,
  version text NOT NULL,
  aggregate_name text NOT NULL,
  "data" bytea NOT NULL
);
CREATE TABLE if not exists oplog_ticket (
  id bigint generated always as identity primary key,
  created_at timestamp with time zone default current_timestamp,
  updated_at timestamp with time zone default current_timestamp,
  "name" text NOT NULL UNIQUE,
  "version" int8 NOT NULL
);
CREATE TABLE if not exists oplog_metadata (
  id bigint generated always as identity primary key,
  created_at timestamp with time zone default current_timestamp,
  entry_id int8 NOT NULL REFERENCES oplog_entry(id),
  "key" text NOT NULL,
  value text NULL
);
create index if not exists idx_oplog_metatadata_key on oplog_metadata(key);
create index if not exists idx_oplog_metatadata_value on oplog_metadata(value);