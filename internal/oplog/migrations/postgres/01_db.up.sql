CREATE TABLE if not exists oplog_entries (
  id bigserial NOT NULL,
  created_at timestamp default current_timestamp,
  updated_at timestamp default current_timestamp,
  hmac bytea NULL,
  kid text NULL,
  aggregate_name text NULL,
  "data" bytea NULL,
  CONSTRAINT oplog_entries_pkey PRIMARY KEY (id)
);
CREATE TABLE if not exists oplog_tickets (
  id bigserial NOT NULL,
  created_at timestamp NULL,
  updated_at timestamp NULL,
  "name" text NULL,
  "version" int8 NULL,
  CONSTRAINT oplog_tickets_pkey PRIMARY KEY (id)
);
CREATE UNIQUE INDEX idx_entry_tickets_name ON oplog_tickets USING btree (name);
CREATE TABLE oplog_metadata (
  id bigserial NOT NULL,
  created_at timestamp NULL,
  entry_id int8 NULL,
  "key" text NULL,
  value text NULL,
  CONSTRAINT oplog_metadata_pkey PRIMARY KEY (id)
);