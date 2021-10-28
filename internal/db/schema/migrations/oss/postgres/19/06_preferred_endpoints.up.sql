begin;

create table host_set_preferred_endpoint (
  create_time wt_timestamp,
  host_set_id wt_public_id not null
    constraint host_set_fkey
    references host_set(public_id)
    on delete cascade
    on update cascade,
  priority wt_priority,
  condition text not null
    constraint condition_must_not_be_too_short
      check(length(trim(condition)) > 4) -- minimum is 'dns:*'
    constraint condition_must_not_be_too_long
      check(length(trim(condition)) < 255)
    constraint condition_has_valid_prefix
      check(
        left(trim(condition), 4) = 'dns:'
          or
        left(trim(condition), 5) = 'cidr:'
       )
    constraint condition_does_not_contain_invalid_chars
      check(
        position('|' in trim(condition)) = 0
          and
        position('=' in trim(condition)) = 0
      ),
  primary key(host_set_id, priority),
  constraint host_set_preferred_endpoint_host_set_id_condition_uq
    unique(host_set_id, condition)
);

-- host_set_immutable_preferred_endpoint() ensures that endpoint conditions
-- assigned to host sets are immutable.
create function
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
    hc.plugin_id,
    hs.name,
    hs.description,
    hs.create_time,
    hs.update_time,
    hs.version,
    hs.attributes,
    -- the string_agg(..) column will be null if there are no associated value objects
    string_agg(distinct concat_ws('=', hspe.priority, hspe.condition), '|') as preferred_endpoints,
    string_agg(distinct hpsm.host_id, '|') as host_ids
  from
    host_plugin_set hs
    join host_plugin_catalog hc                        on hs.catalog_id = hc.public_id
    left outer join host_set_preferred_endpoint hspe   on hs.public_id = hspe.host_set_id
    left outer join host_plugin_set_member hpsm        on hs.public_id = hpsm.set_id
  group by hs.public_id, hc.plugin_id;
comment on view host_plugin_host_set_with_value_obj is
'host plugin host set with its associated value objects';

commit;