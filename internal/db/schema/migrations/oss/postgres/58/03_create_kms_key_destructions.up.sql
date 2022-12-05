begin;

  create table kms_data_key_version_destruction_job (
    key_id kms_private_id primary key -- one job per key version
      references kms_data_key_version (private_id)
        on delete cascade -- Note: instead of restrict, we cascade the delete to this job when the key version is deleted
        on update cascade,
    create_time wt_timestamp not null
  );
  comment on table kms_data_key_version_destruction_job is
    'Table holding running and pending data key version destruction jobs';

  create trigger immutable_columns before update on kms_data_key_version_destruction_job
    for each row execute procedure immutable_columns('key_id', 'create_time');


  create table kms_data_key_version_destruction_job_run (
    key_id kms_private_id not null
      references kms_data_key_version_destruction_job (key_id)
        on delete cascade
        on update cascade
        deferrable initially deferred,
    table_name text not null,
    total_count bigint not null
      constraint total_count_cannot_be_negative
        check (total_count > 0), -- Must not be 0
    completed_count bigint not null default 0
      constraint completed_count_cannot_be_negative
        check (completed_count >= 0),
    is_running boolean not null default false,
    
    primary key (key_id, table_name),
    constraint completed_count_less_than_equal_to_total_count
      check (completed_count <= total_count),
    constraint is_running_only_when_not_completed
      check ((completed_count < total_count) or (completed_count = total_count and not is_running))
  );
  comment on table kms_data_key_version_destruction_job_run is
    'Table holding per-table runs of data key version destruction jobs';

  create trigger immutable_columns before update on kms_data_key_version_destruction_job_run
    for each row execute procedure immutable_columns('key_id', 'table_name', 'total_count');

  create unique index kms_data_key_version_destruction_job_run_is_running_uq
    on kms_data_key_version_destruction_job_run (is_running) where is_running = true; -- allow only one running run

  -- A view that holds all the names of tables that reference the
  -- data_key_version.private_id column as a foreign key.
  -- Excludes tables that should not be used in a job run.
  create view kms_data_key_version_destruction_job_run_allowed_table_name as
    select distinct
      r.table_name
    from
      information_schema.constraint_column_usage          u
    inner join information_schema.referential_constraints fk
      on u.constraint_catalog = fk.unique_constraint_catalog and
        u.constraint_schema = fk.unique_constraint_schema and
        u.constraint_name = fk.unique_constraint_name
    inner join information_schema.key_column_usage        r
      on r.constraint_catalog = fk.constraint_catalog and
        r.constraint_schema = fk.constraint_schema and
        r.constraint_name = fk.constraint_name
    where
      u.column_name = 'private_id' and
      u.table_name = 'kms_data_key_version' and
      -- These tables reference the right column, but are not allowed as a destruction
      -- job run table name.
      r.table_name not in ('oplog_entry', 'kms_data_key_version_destruction_job');

  create function kms_data_key_table_name_valid() returns trigger
  as $$
  begin
    if new.table_name not in (select table_name from kms_data_key_version_destruction_job_run_allowed_table_name) then
      raise exception 'invalid table name % (must be table that references kms_data_key_version.private_id)', new.table_name;
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function kms_data_key_table_name_valid is
    'Function used to determine whether a table name is valid for a destruction job run';

  create trigger kms_data_key_table_name_valid before insert on kms_data_key_version_destruction_job_run
    for each row execute procedure kms_data_key_table_name_valid();
  

  -- Used to list progress of all destruction jobs
  create view kms_data_key_version_destruction_job_progress as
    select
      j.key_id,
      rk.scope_id,
      j.create_time,
      case
        when bool_or(r.is_running) then 'running'
        when sum(r.total_count) = sum(r.completed_count) then 'completed'
        else 'pending'
      end status,
      sum(r.completed_count) as completed_count,
      sum(r.total_count) as total_count
    from kms_data_key_version_destruction_job           j
    inner join kms_data_key_version_destruction_job_run r
      on j.key_id = r.key_id
    inner join kms_data_key_version                     dkv
      on j.key_id = dkv.private_id
    inner join kms_data_key                             dk
      on dkv.data_key_id = dk.private_id
    inner join kms_root_key                             rk
      on dk.root_key_id = rk.private_id
    group by (j.key_id, rk.scope_id);

commit;
