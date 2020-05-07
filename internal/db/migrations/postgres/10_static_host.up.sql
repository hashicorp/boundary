begin;

  create table static_host_catalog (
    public_id wt_public_id primary key,
    scope_id wt_public_id not null, -- TODO: add fk
    name text,
    create_time timestamp with time zone default current_timestamp,
    update_time timestamp with time zone default current_timestamp,
    unique(scope_id, name)
  );

  create table static_host (
    public_id wt_public_id primary key,
    static_host_catalog_id wt_public_id not null
      references static_host_catalog
      on delete cascade
      on update cascade,
    name text,
    address text not null, -- TODO: add check constraint
    create_time timestamp with time zone default current_timestamp,
    update_time timestamp with time zone default current_timestamp,
    unique(static_host_catalog_id, name)
  );

  create table static_host_set (
    public_id wt_public_id primary key,
    static_host_catalog_id wt_public_id not null
      references static_host_catalog
      on delete cascade
      on update cascade,
    name text,
    create_time timestamp with time zone default current_timestamp,
    update_time timestamp with time zone default current_timestamp,
    unique(static_host_catalog_id, name)
  );

  create table static_host_set_member (
    static_host_set_id wt_public_id,
    static_host_id wt_public_id,
    primary key(static_host_set_id, static_host_id)
  );

commit;
