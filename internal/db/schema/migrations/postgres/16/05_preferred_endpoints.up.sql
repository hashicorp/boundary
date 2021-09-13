begin;

create table host_set_preferred_endpoint (
  host_set_id wt_public_id not null
    constraint host_set_id_fkey
    references host_set(public_id)
    on delete cascade
    on update cascade,
  priority int not null
    check(priority > 0),
  condition text not null
    check(length(condition) > 0),
  primary key(host_set_id, priority)
);

-- host_set_immutable_preferred_endpoint() ensures that endpoint conditions
-- assigned to host sets are immutable.
create or replace function
  host_set_immutable_preferred_endpoint()
  returns trigger
as $$
begin
  raise exception 'preferred endpoints are immutable';
end;
$$ language plpgsql;

create trigger immutable_preferred_endpoint
  before update on host_set_preferred_endpoint
  for each row execute procedure host_set_immutable_preferred_endpoint();

commit;
