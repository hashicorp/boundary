begin;

  -- TODO: Add domain for timestamp

  create table static_host_catalog (
    public_id wt_public_id primary key,
    -- scope_id wt_public_id not null
      -- references iam_scope (public_id)
      -- on delete cascade
      -- on update cascade,
    scope_id wt_public_id not null,
    name text,
    description text,
    create_time timestamp with time zone default current_timestamp,
    update_time timestamp with time zone default current_timestamp,
    unique(scope_id, name)
  );

  create table static_host (
    public_id wt_public_id primary key,
    static_host_catalog_id wt_public_id not null
      references static_host_catalog (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    address text not null, -- TODO: add check constraint
    create_time timestamp with time zone default current_timestamp,
    update_time timestamp with time zone default current_timestamp,
    unique(static_host_catalog_id, name)
  );

  create table static_host_set (
    public_id wt_public_id primary key,
    static_host_catalog_id wt_public_id not null
      references static_host_catalog (public_id)
      on delete cascade
      on update cascade,
    name text,
    description text,
    create_time timestamp with time zone default current_timestamp,
    update_time timestamp with time zone default current_timestamp,
    unique(static_host_catalog_id, name)
  );

  create table static_host_set_member (
    static_host_set_id wt_public_id
      references static_host_set (public_id)
      on delete cascade
      on update cascade,
    static_host_id wt_public_id
      references static_host (public_id)
      on delete cascade
      on update cascade,
    primary key(static_host_set_id, static_host_id)
  );

commit;

