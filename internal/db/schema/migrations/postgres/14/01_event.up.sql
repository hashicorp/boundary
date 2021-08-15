begin;

/*
┌─────────────────┐                               
│iam_scope_global │                               
├─────────────────┤                               
│                 │                               
└─────────────────┘                               
         ┼                                        
         │                                        
         ┼                                        
         ┼                                        
┌─────────────────┐                               
│  event_config   │           ┌──────────────────┐
├─────────────────┤           │event_type_enabled│
│ public_id       │          ╱├──────────────────┤
│ scope_id        │┼────────○─│config_id         │
| name            │          ╲│event_type        │
│ description     |           |                  |
| create_time     |           └──────────────────┘
| update_time     │                     |
│ version         |                     |
└─────────────────┘                     |
         ┼                              ┼         
         ┼                              │         
         │                              │         
         │                             ╱│╲        
         ○                     ┌─────────────────┐
        ╱│╲                   ╱│ event_type_enm  │
┌─────────────────┐     ┌───┬──├─────────────────┤
│   event_sink    │     │   │ ╲│                 │
├─────────────────┤     │   │  └─────────────────┘
│public_id        │     │   │                     
│config_id        │     │   │                     
│                 │     │   │                     
└─────────────────┘     │   │                     
         ┼ ┼            │   │                     
         │ │            │   │                     
         │ │            │   │                     
         │ │            │   │                     
         │ │            │   │                     
         │ │            │   └────────────────┐    
         │ │            │                    │    
         │ └────────────┼────────┐           │    
         ○              │        │           │    
        ╱│╲             │        │           │    
┌─────────────────┐     │        │           │    
│ event_file_sink │     │        │           │    
├─────────────────┤     │        │           │    
│ public_id       │┼────┘        ○           │    
│ config_id       │             ╱│╲          │    
│ event_type      │     ┌─────────────────┐  │    
│ format_type     │     │event_stderr_sink│  │    
│ allow_filters   │     ├─────────────────┤  │    
│ deny_filters    │     │ public_id       │  │    
│ path            │     │ config_id       │  │    
│ file_name       │     │ event_type      │┼─┘    
│ rotate_bytes    │     │ format_type     │       
│ rotate_duration │     │ allow_filters   │       
│ rotate_max_files│     │ deny_filters    │       
└─────────────────┘     └─────────────────┘       
         ┼                        ┼               
         │                        │               
         │                        │               
         │  ┌─────────────────┐   │               
         │ ╱│event_format_type│╲  │               
         └──├─────────────────┤───┘               
           ╲│                 │╱                  
            └─────────────────┘                                                                                     
*/

create table event_type_enm (
    name text primary key
        constraint only_predefined_event_types_allowed
        check (
            name in (
                'every',
                'error',
                'audit',
                'observation',
                'system'
            )
        )
);

comment on table event_type_enm is
'event_type_enm is an enumeration table for the valid event types within '
'the domain';

create trigger 
  immutable_columns
before
update on event_type_enm
  for each row execute procedure immutable_columns('name');

create table event_format_type_enm (
    name text primary key
        constraint only_predefined_event_format_types_allowed
        check (
            name in (
                'cloudevents-json',
                'cloudevents-text',
                'hclog-text',
                'hclog-json'
            )
        )
);

comment on table event_format_type_enm is
'event_format_type_enm is an enumeration table for the valid event format types '
'within the domain';

create trigger 
  immutable_columns
before
update on event_format_type_enm
  for each row execute procedure immutable_columns('name');

create table event_config (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
        constraint iam_scope_global_fkey
            references iam_scope_global(scope_id)
            on delete cascade
            on update cascade,
        constraint event_config_scope_id_uq -- only allow one config per scope
            unique(scope_id),
    name wt_name,
    constraint event_config_name_scope_id_uq
        unique(scope_id, name), 
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version
);

comment on table event_config is
'event_config is a table where each row defines the event configuration for '
'a scope.  Currently, the only supported scope is global';

create trigger 
  immutable_columns
before
update on event_config
  for each row execute procedure immutable_columns(
      'public_id',
      'scope_id',
      'create_time'
);

create trigger
    update_version_column
after update on event_config
    for each row execute procedure update_version_column();

create trigger
    update_time_column
before update on event_config
    for each row execute procedure update_time_column();

create trigger
    default_create_time_column
before insert on event_config
    for each row execute procedure default_create_time();

create table event_type_enabled (
    config_id wt_public_id
        constraint event_config_fkey
            references event_config(public_id)
            on delete cascade
            on update cascade,
    event_type text not null
        constraint event_type_enm_fkey
            references event_type_enm(name)
            on delete restrict
            on update cascade,
    primary key(event_type, config_id)
);

comment on table event_type_enabled is
'event_type_enabled is a table where each row represents that eventing has '
'been enabled for the specified event type in an event configuration';

create table event_sink(
    public_id wt_public_id primary key,
    config_id wt_public_id not null
        constraint event_config_fkey
            references event_config(public_id)
            on delete cascade
            on update cascade,
    constraint event_sink_config_id_public_id_uq
      unique(config_id, public_id)
);

comment on table event_sink is 
'event_sink is a table where each row represents a configured event sink';

-- insert_event_sink_subtype() is a before insert trigger
-- function for subtypes of event_sink
create function insert_event_sink_subtype()
    returns trigger
as $$
begin
    insert into event_sink
        (public_id, config_id)
    values
        (new.public_id, new.config_id);
    return new;
end;
$$ language plpgsql;

-- delete_event_sink_subtype() is an after delete trigger
-- function for subtypes of event_sink
create function delete_event_sink_subtype()
    returns trigger
as $$
begin
    delete from event_sink
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
end;
$$ language plpgsql;

create table event_file_sink(
    public_id wt_public_id primary key,
    config_id wt_public_id not null,
    event_type text not null
        constraint event_type_enm_fkey
            references event_type_enm(name)
            on delete restrict
            on update cascade,
    format_type text not null
        constraint event_format_type_enm_fkey
            references event_format_type_enm(name)
            on delete restrict
            on update cascade,
    allow_filter wt_bexprfilter,
    deny_filter wt_bexprfilter,
    path text not null 
        constraint path_not_empty
            check (
                length(trim(path)) > 0
            ),
    filename text not null
        constraint filename_not_empty
            check (
                length(trim(filename)) > 0
            ),
    constraint path_filename_uq
        unique(path, filename), -- ensure each sink is writing to a unique file
    rotate_bytes int
        constraint rotate_bytes_null_or_greater_than_zero
            check(
                rotate_bytes > 0
            ),
    rotate_duration interval
        constraint rotate_duration_null_or_greater_than_zero
            check(
                rotate_duration > '0'::interval
            ),
    rotate_max_files int
        constraint rotate_max_files_null_or_greater_than_zero
            check(
                rotate_max_files > 0
            ),
    constraint event_sink_fkey
      foreign key(config_id, public_id)
      references event_sink(config_id, public_id)
      on delete cascade
      on update cascade
);

comment on table event_file_sink is 
'event_file_sink is a table where each entry represents a configured event file '
'sink';

create trigger
  immutable_columns
before
update on event_file_sink
  for each row execute procedure immutable_columns(
      'public_id', 
      'config_id'
);

create trigger
    insert_event_sink_subtype 
before insert on event_file_sink
    for each row execute procedure insert_event_sink_subtype();

create trigger
    delete_event_sink_subtype 
after delete on event_file_sink
    for each row execute procedure delete_event_sink_subtype();

create table event_stderr_sink(
    public_id wt_public_id primary key,
    config_id wt_public_id not null
        constraint event_config_fkey
            references event_config(public_id)
            on delete cascade
            on update cascade,
    event_type text not null
        constraint event_type_enm_fkey
            references event_type_enm(name)
            on delete restrict
            on update cascade,
    format_type text not null
    constraint event_format_type_enm_fkey
        references event_format_type_enm(name)
        on delete restrict
        on update cascade,
    allow_filter wt_bexprfilter,
    deny_filter wt_bexprfilter,
    constraint event_sink_fkey
      foreign key(config_id, public_id)
      references event_sink(config_id, public_id)
      on delete cascade
      on update cascade
);

comment on table event_stderr_sink is
'event_stderr_sink is a table where each entry represents a configured stderr '
'sink';

create trigger
  immutable_columns
before
update on event_stderr_sink
  for each row execute procedure immutable_columns(
      'public_id', 
      'config_id'
);

create trigger
    insert_event_sink_subtype
before insert on event_stderr_sink
    for each row execute procedure insert_event_sink_subtype();

create trigger 
    delete_event_sink_subtype
after delete on event_stderr_sink
    for each row execute procedure delete_event_sink_subtype();

commit;
