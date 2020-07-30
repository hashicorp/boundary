begin;

-- For now at least the IDs will be the same as the name, because this allows us
-- to not have to persist some generated ID to worker and controller nodes.
-- Eventually we may want them to diverge, so we have both here for now.

create table servers (
    private_id text primary key,
    name text unique,
    type text,
    description text,
    first_seen_time wt_timestamp,
    last_seen_time wt_timestamp
  );