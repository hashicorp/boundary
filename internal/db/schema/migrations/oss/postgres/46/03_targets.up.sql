-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table target
    add constraint target_project_id_public_id_uq
      unique(project_id, public_id)
  ;

  -- target_credential_library
  alter table target_credential_library
    add column project_id wt_public_id
  ;

  update target_credential_library
     set (project_id) =
         (select project_id
            from target
           where target.public_id = target_credential_library.target_id
         )
  ;

  alter table target_credential_library
    alter column project_id set not null,
    drop constraint target_credential_library_pkey,
    add primary key(project_id, target_id, credential_library_id, credential_purpose),
    drop constraint target_fkey,
    add constraint target_fkey
      foreign key (project_id, target_id)
        references target (project_id, public_id)
        on delete cascade
        on update cascade,
    drop constraint credential_library_fkey,
    add constraint credential_library_fkey
      foreign key (project_id, credential_library_id)
        references credential_library (project_id, public_id)
        on delete cascade
        on update cascade
  ;

  drop trigger immutable_columns on target_credential_library;
  create trigger immutable_columns before update on target_credential_library
    for each row execute function immutable_columns('target_id', 'project_id', 'credential_library_id', 'credential_purpose', 'create_time');

  -- target_static_credential
  alter table target_static_credential
    add column project_id wt_public_id
  ;

  update target_static_credential
     set (project_id) =
         (select project_id
            from target
           where target.public_id = target_static_credential.target_id
         )
  ;

  alter table target_static_credential
    alter column project_id set not null,
    drop constraint target_static_credential_pkey,
    add primary key(project_id, target_id, credential_static_id, credential_purpose),
    drop constraint target_fkey,
    add constraint target_fkey
      foreign key (project_id, target_id)
        references target (project_id, public_id)
        on delete cascade
        on update cascade,
    drop constraint credential_static_fkey,
    add constraint credential_static_fkey
      foreign key (project_id, credential_static_id)
        references credential_static (project_id, public_id)
        on delete cascade
        on update cascade
  ;

  drop trigger immutable_columns on target_static_credential;
  create trigger immutable_columns before update on target_static_credential
    for each row execute procedure immutable_columns('target_id', 'project_id', 'credential_static_id', 'credential_purpose', 'create_time');

  -- target_host_set
  alter table target_host_set
    add column project_id wt_public_id
  ;

  update target_host_set
     set (project_id) =
         (select project_id
            from target
           where target.public_id = target_host_set.target_id
         )
  ;

  alter table target_host_set
    alter column project_id set not null,
    drop constraint target_host_set_pkey,
    add primary key(project_id, target_id, host_set_id),
    drop constraint target_fkey,
    add constraint target_fkey
      foreign key (project_id, target_id)
        references target (project_id, public_id)
        on delete cascade
        on update cascade,
    drop constraint target_host_set_host_set_id_fkey,
    add constraint host_set_fkey
      foreign key (project_id, host_set_id)
        references host_set (project_id, public_id)
        on delete cascade
        on update cascade
  ;

  drop trigger immutable_columns on target_host_set;
  create trigger immutable_columns before update on target_host_set
    for each row execute function immutable_columns('target_id', 'project_id', 'host_set_id', 'create_time');

  drop function target_host_set_scope_valid cascade;
  drop function if exists target_credential_library_scope_valid cascade;
  drop function if exists target_static_credential_scope_valid cascade;

  create or replace function insert_project_id() returns trigger
  as $$
  begin
    select project_id into new.project_id
      from target
     where target.public_id = new.target_id;
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_project_id() is
    'insert_project_id will set the missing value for project_id, which is derived from the target table.';

  create trigger insert_target_static_credential before insert on target_static_credential
    for each row execute procedure insert_project_id();
  create trigger insert_target_credential_library before insert on target_credential_library
    for each row execute function insert_project_id();
  create trigger insert_target_host_set before insert on target_host_set
    for each row execute function insert_project_id();

commit;
