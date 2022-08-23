begin;

create table target_host (
  target_id wt_public_id not null,
  host_id wt_public_id not null,
  create_time wt_timestamp NULL,
  project_id wt_public_id not null,
  -- Ensure this is unique per target id and references the project
  constraint target_host_set_pkey
    primary key (project_id, target_id, host_id),
  -- Ensure this is deleted if a host or project is deleted
  constraint host_set_fkey
    foreign key (project_id, host_id)
      references host(project_id, public_id) 
      on delete cascade
      on update cascade,
  -- Ensure this is deleted if a target is deleted
  constraint target_fkey
    foreign key (project_id, target_id)
      references target(project_id, public_id)
      on delete cascade
      on update cascade
);

create trigger immutable_columns before update on target_host
  for each row execute procedure immutable_columns('target_id', 'project_id', 'host_id', 'create_time');

create trigger insert_target_host_set before insert on target_host
  for each row execute procedure insert_project_id();

-- View of all hosts in a target
create view target_source_host as
  select h.public_id,
    h.catalog_id,
    th.target_id
  from target_host th,
    host h
  where h.public_id = th.host_id;

commit;