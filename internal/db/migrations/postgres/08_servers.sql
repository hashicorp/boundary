begin;

create table workers (
    id text primary key,
    name text unique,
    description text,
    first_seen_time wt_timestamp,
    last_seen_time wt_timestamp
  );

create table controllers (
    id text primary key,
    name text unique,
    description text,
    first_seen_time wt_timestamp,
    last_seen_time wt_timestamp
  );
