begin;

-- For now at least the IDs will be the same as the name, because this allows us
-- to not have to persist some generated ID to worker and controller nodes.
-- Eventually we may want them to diverge, so we have both here for now.

create table servers (
    private_id text,
    type text,
    name text not null unique,
    description text,
    address text,
    create_time wt_timestamp,
    update_time wt_timestamp,
    primary key (private_id, type)
  );
  
create trigger 
  immutable_create_time
before
update on servers
  for each row execute procedure immutable_create_time_func();
  
create trigger 
  default_create_time_column
before
insert on servers
  for each row execute procedure default_create_time();

commit;
