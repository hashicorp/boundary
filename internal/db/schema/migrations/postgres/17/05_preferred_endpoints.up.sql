begin;

create table host_set_preferred_endpoint (
  create_time wt_timestamp,
  host_set_id wt_public_id not null
    constraint host_set_fkey
    references host_set(public_id)
    on delete cascade
    on update cascade,
  priority int not null
    check(priority > 0),
  condition text not null
    check(length(condition) > 0),
  primary key(host_set_id, priority),
  unique(host_set_id, condition)
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

-- host_plugin_host_set_with_value_obj is useful for reading a plugin host set with its
-- associated value objects (preferred endpoints) as columns with delimited
-- values. The delimiter depends on the value objects (e.g. if they need
-- ordering).
create view host_plugin_host_set_with_value_obj as
select
  hs.public_id,
  hs.catalog_id,
  hs.name,
  hs.description,
  hs.create_time,
  hs.update_time,
  hs.version,
  hs.attributes,
  -- the string_agg(..) column will be null if there are no associated value objects
  string_agg(distinct concat_ws('=', hspe.priority, hspe.condition), '|') as preferred_endpoints
from
  host_plugin_set hs
  left outer join host_set_preferred_endpoint hspe on hs.public_id = hspe.host_set_id
group by hs.public_id;
comment on view host_plugin_host_set_with_value_obj is
'host plugin host set with its associated value objects';

commit;