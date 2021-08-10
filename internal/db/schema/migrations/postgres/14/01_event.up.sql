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
│ sink_id         │             ╱│╲          │    
│ event_type      │     ┌─────────────────┐  │    
│ format_type     │     │event_stderr_sink│  │    
│ allow_filters   │     ├─────────────────┤  │    
│ deny_filters    │     │ public_id       │  │    
│ path            │     │ sink_id         │  │    
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

create table event_config (
    public_id wt_public_id primary key,
    scope_id wt_scope_id not null
        constraint iam_scope_global_fkey
            references iam_scope_global(scope_id)
            on delete cascade
            on update cascade,
        constraint scope_id_uq -- only allow one config per scope
            unique (scope_id),
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version
);
comment on table event_config is
'event_config is a table where each row defines the event configuration for '
'a scope.  Currently, the only supported scope is global';

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
            references event_type_enm (name)
            on delete restrict
            on update cascade,
    primary key (config_id, event_type)
);
comment on table event_type_enabled is
'event_type_enabled is a table where each row represents that eventing has '
'been enabled for the specified event type in an event configuration';


create table event_sink(
    public_id wt_public_id primary key,
    config_id wt_public_id 
        constraint event_config_fkey
            references event_config(public_id)
            on delete cascade
            on update cascade
);
comment on table event_sink is 
'event_sink is a table where each row represents a configured event sink';

create table event_file_sink(
    public_id wt_public_id primary key,
    sink_id wt_public_id not null
        constraint sink_id_fkey
            references event_sink(public_id)
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
                rotate_bytes is null
                    or
                rotate_bytes > 0
            ),
    rotate_duration interval
        constraint rotate_duration_null_or_greater_than_zero
            check(
                rotate_duration is null
                    or
                rotate_duration > '0'::interval
            ),
    rotate_max_files int
        constraint rotate_max_files_null_or_greater_than_zero
            check(
                rotate_max_files is null
                    or
                rotate_max_files > 0
            )
);
comment on table event_file_sink is 
'event_file_sink is a table where each entry represents a configured event file '
'sink';

create table event_stderr_sink(
    public_id wt_public_id primary key,
    sink_id wt_public_id not null
        constraint sink_id_fkey
        references event_sink(public_id)
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
    deny_filter wt_bexprfilter
);

comment on table event_stderr_sink is
'event_stderr_sink is a table where each entry represents a configured stderr '
'sink';

commit;
