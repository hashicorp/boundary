begin;

create table target_host(
  target_id wt_public_id
    references target(public_id)
    on delete cascade
    on update cascade,
  host_id wt_public_id
    references host(public_id)
    on delete cascade
    on update cascade,
  primary key(target_id, host_id),
  create_time wt_timestamp
);

create trigger 
  immutable_columns
before
update on target_host
  for each row execute procedure immutable_columns('target_id', 'host_id', 'create_time');

create or replace function
  target_host_scope_valid()
  returns trigger
as $$
begin
    perform from
      host_catalog hc,
      host h,
      target t,
      iam_scope s
    where
      hc.public_id = h.catalog_id and 
      hc.scope_id = t.scope_id and
      t.public_id = new.target_id;
if not found then
  raise exception 'target scope and host scope are not equal';
end if;
return new;
end;
$$ language plpgsql;

create trigger 
  target_host_scope_valid
before
insert on target_host
  for each row execute procedure target_host_scope_valid();

create view target_host_view
as
select 
  h.public_id,
  h.catalog_id,
  th.target_id
from
  target_host th,
  host h
where
  h.public_id = th.host_id;

commit;