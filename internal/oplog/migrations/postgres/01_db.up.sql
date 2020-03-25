CREATE TABLE if not exists oplog_entry (
  id bigserial NOT NULL,
  created_at timestamp default current_timestamp,
  updated_at timestamp default current_timestamp,
  version text NOT NULL,
  aggregate_name text NOT NULL,
  "data" bytea NOT NULL,
  CONSTRAINT oplog_entry_pkey PRIMARY KEY (id)
);
CREATE TABLE if not exists oplog_ticket (
  id bigserial NOT NULL,
  created_at timestamp default current_timestamp,
  updated_at timestamp default current_timestamp,
  "name" text NOT NULL,
  "version" int8 NOT NULL,
  CONSTRAINT oplog_ticket_pkey PRIMARY KEY (id)
);
CREATE UNIQUE INDEX if not exists idx_entry_ticket_name ON oplog_ticket USING btree (name);
CREATE TABLE if not exists oplog_metadata (
  id bigserial NOT NULL,
  created_at timestamp default current_timestamp,
  entry_id int8 NOT NULL,
  "key" text NOT NULL,
  value text NULL,
  CONSTRAINT oplog_metadata_pkey PRIMARY KEY (id)
);