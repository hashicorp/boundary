begin;

/*
   ┌─────────────────┐            ┌──────────────────┐
   │     wt_member   │            |   job_type_enm   |
   ├─────────────────┤            ├──────────────────┤
   │  public_id      |          ╱ |                  |
   |  name           |┼────────○─ |                  |
   |  location       │          ╲ |                  |
   |  job            |            └──────────────────┘
   |  create_time    |
   |  update_time    |
   |  version        |
   └─────────────────┘
            ┼ 
            │
            ┼
            ┼
   ┌─────────────────┐
   │  pet_type       │
   ├─────────────────┤
   │ public_id       │
   │ owner           │
   │                 │
   │                 │
   └─────────────────┘
            ┼ ┼
            │ │
            │ └────────────┼────────┐
            │                       │
            ○                       ○ 
           ╱│╲                     ╱│╲
   ┌─────────────────┐       ┌─────────────────┐     
   │   pet_dog_type  │       │   pet_cat_type  │
   ├─────────────────┤       ├─────────────────┤            ┌───────────────────────┐
   │ public_id       │       | public_id       |            |   cat_coat_type_enm   |
   │ owner           |       | owner           |            ├───────────────────────┤
   | name            |       | name            |          ╱ |                       |
   | breed           |       | breed           |┼────────○─ |                       |
   | age             │       | age             |          ╲ |                       |
   |                 |       | color           |            |                       |
   │                 │       | coat_length     |            └───────────────────────┘
   └─────────────────┘       └─────────────────┘

*/

-- create an enumeration table where we restrict
-- the values allowed into the `name` column
-- enm tables tend to be at the top
create table job_type_enm (
    title text primary key
        constraint only_predefined_job_types_allowed
        check (
            title in (
                'be-engineer',
                'fe-engineer',
                'product',
                'management',
                'pete'
            )
        )
);

comment on table job_type_enm is
'job_type_enm is an enumeration table that is within '
'the domain';

-- all enm tables need to have the column immutable
create trigger
    immutable_columns
before
update on job_type_enm
    for each row execute procedure immutable_columns('title');

create table cat_coat_type_enm (
    name text primary key
        constraint only_predefined_coat_types_allowed
            check (
                name in (
                    'hairless',
                    'short',
                    'medium',
                    'long'
                )
            )
);

comment on table cat_coat_type_enm is
'cat_coat_type_enm is an enumeration table that '
'defines cat coat type length';

-- all enm tables need to have the column immutable
create trigger
    immutable_columns
before
update on cat_coat_type_enm
    for each row execute procedure immutable_columns('title');

create table wt_member (
    public_id wt_public_id primary key,
    name wt_name,
    location text,
    job text not null -- no comma here, since we are giving a constraint to this column
        constraint job_type_enm_fkey
            references job_type_enm(name)
            on delete restrict -- always restrict on delete for enm types
            on update cascade,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version
);
-- always add an empty line after declaring a table for mike gaffney's vim plugin 

-- every table should have a comment if possible!
comment on table wt_member is
'wt_member is a table which each row describes a boundary team member';

-- the following triggers are used for each domain type column defined above
create trigger
    update_version_column
after update on wt_member
    for each row execute procedure update_version_column();

-- sql isn't picky about spacing
-- but to show empathy and kindness to each other, grouping
-- like ideas is encouraged to enhance readability
create trigger 
    update_time_column
before update on wt_member
    for each row execute procedure update_time_column();

create trigger
    default_create_time_column
before insert on wt_member
    for each row execute procedure default_create_time();

-- this is a bad example of a parent type but it tries
create table pet_type (
    public_id wt_public_id,
    owner string not null
        constraint wt_member_fkey
            references wt_member(name)
            on delete cascade
            on update cascade,
    constraint public_id_owner_uq
        unique(public_id, owner)
);

-- triggers below for the subtypes pet_dog_type, and pet_cat_type

-- insert_event_sink_subtype() is a before insert trigger
-- function for subtypes of pet_type
create function insert_pet_type_subtype()
    returns trigger
as $$
begin
    insert into pet_type
        (public_id, owner)
    values
        (new.public_id, new.owner);
    return new;
end;
$$ language plpgsql;

-- delete_pet_type_subtype() is an after delete trigger
-- function for subtypes of pet_type
create function delete_pet_type_subtype()
    returns trigger
as $$
begin
    delete from pet_type
    where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
end;
$$ language plpgsql;

--subtable names tend to adhere to parentTableWordOne_subTable_parentTableWordTwo
create table pet_dog_type (
    public_id wt_public_id,
    owner string not null
        constraint wt_member_fkey
            references wt_member(name)
            on delete cascade
            on update cascade,
    name string,
    breed string,
    age int,
    constraint owner_name_age_uq
        unique(owner, name, age)
);

create trigger
    insert_pet_type_subtype 
before insert on pet_dog_type
    for each row execute procedure insert_pet_type_subtype();

create trigger
    delete_pet_type_subtype 
after delete on pet_dog_type
    for each row execute procedure delete_pet_type_subtype();

comment on table pet_dog_type is
'pet_dog_type is a table where each row is a wt_members '
'dog';

create table pet_cat_type (
    public_id wt_public_id,
    owner string not null
        constraint wt_member_fkey
            references wt_member(name)
            on delete cascade
            on update cascade,
    name string,
    breed string,
    age int,
    color string,
    coat_length string not null
        constraint cat_coat_type_fkey
            references cat_coat_type_enm(name)
            on delete restrict
            on update cascade,
    constraint owner_name_age_uq
        unique(owner, name, age)
);

create trigger
    insert_pet_type_subtype 
before insert on pet_cat_type
    for each row execute procedure insert_pet_type_subtype();

create trigger
    delete_pet_type_subtype 
after delete on pet_cat_type
    for each row execute procedure delete_pet_type_subtype();

comment on table pet_cat_type is
'pet_cat_type is a table where each row is a wt_members '
'cat';

commit;