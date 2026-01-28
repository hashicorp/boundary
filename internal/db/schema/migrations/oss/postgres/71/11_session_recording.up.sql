-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create domain rec_timestamp as timestamptz default null;
  comment on domain rec_timestamp is
    'a nullable timestamp with a time zone used for start and end times of recordings';


  create table recording_session_state_enm (
    name text primary key
      constraint only_predefined_states_allowed
        check(name in ('unknown', 'started', 'available'))
  );
  comment on table recording_session_state_enm is
    'recording_session_state_enm holds valid values for the state of a recording_session row.';

  insert into recording_session_state_enm (name)
  values
    ('unknown'),
    ('started'),
    ('available');

  create trigger immutable_columns before update on recording_session_state_enm
    for each row execute procedure immutable_columns('name');

  create table recording_session (
    public_id wt_public_id primary key,
    storage_bucket_id wt_public_id not null
      constraint storage_plugin_storage_bucket_fkey
        references storage_plugin_storage_bucket (public_id)
        on delete restrict -- Storage buckets with session recordings cannot be deleted
        on update cascade,
    session_id wt_public_id null -- Can be null if associated session has been deleted
      constraint session_fkey
        references session (public_id)
        on delete set null -- Set null if associated session is deleted
        on update cascade
      constraint recording_session_session_id_uq unique,
    user_scope_hst_id wt_url_safe_id not null
      constraint user_iam_scope_hst_fk
        references iam_scope_hst (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    user_hst_id wt_url_safe_id not null
      constraint iam_user_hst_fk
        references iam_user_hst (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    target_project_hst_id wt_url_safe_id not null
      constraint project_iam_scope_hst_fk
        references iam_scope_hst (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    target_hst_id wt_url_safe_id not null
      constraint target_ssh_hst_fk
        references target_ssh_hst (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    host_catalog_hst_id wt_url_safe_id not null
      constraint host_catalog_history_base_fk
        references host_catalog_history_base (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    host_hst_id wt_url_safe_id not null
      constraint host_history_base_fk
        references host_history_base (history_id)
        on delete restrict -- History records with session recordings cannot be deleted
        on update cascade,
    endpoint text null,
    create_time wt_timestamp not null,
    update_time wt_timestamp not null,
    start_time rec_timestamp null, -- When the session recording was started in the worker
    -- When the session recording ended in the worker
    -- Guaranteed to be recorded monotonically relative to start_time.
    end_time rec_timestamp null
      constraint end_time_null_or_after_start_time
        check (end_time > start_time),
    state text not null default 'started'
      constraint recording_session_state_enm_fkey
        references recording_session_state_enm (name)
        on delete restrict
        on update cascade,
    error_details wt_sentinel not null default wt_to_sentinel('no error details'), 
    constraint recording_session_session_id_public_id_uq
      unique (session_id, public_id),
    -- Error details are allowed two different types of values:
    --  - e'\ufffeno error details\uffff', the sentinel value for "no error details", only when the recording is in the started or available state.
    --  - some error message when the recording is in the unknown state.
    constraint error_details_set_iff_state_not_started
      check (
        (error_details = wt_to_sentinel('no error details') and state in ('started', 'available')) or
        (error_details != wt_to_sentinel('no error details') and state = 'unknown')
      )
  );
  comment on table recording_session is
    'recording_session holds metadata for the recording of a session. It outlives the session itself.';

  create trigger update_time_column before update on recording_session
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on recording_session
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on recording_session
    for each row execute procedure immutable_columns('public_id', 'storage_bucket_id', 'create_time',
        'user_scope_hst_id', 'user_hst_id');

  create trigger set_once_columns before update on recording_session
    for each row execute procedure set_once_columns('start_time', 'end_time');

  create function insert_session_recording() returns trigger
  as $$
  declare
    _session session%rowtype;
    _host host%rowtype;
  begin
    if new.session_id is null then
      raise exception 'a new recorded session must have a session_id';
    end if;
    if new.state is not null and new.state != 'started' then
      raise exception 'state can only be set to ''started'' on insert';
    end if;

    select * into strict _session
      from session
     where public_id = new.session_id;

    new.endpoint = _session.endpoint;

    select history_id into strict new.user_hst_id
      from iam_user_hst
     where public_id = _session.user_id
       and valid_range @> current_timestamp;

    select iam_scope_hst.history_id into strict new.user_scope_hst_id
      from iam_scope_hst
     where public_id = (select scope_id
                          from iam_user
                         where public_id = _session.user_id)
       and valid_range @> current_timestamp;

    select history_id into strict new.target_project_hst_id
      from iam_scope_hst
     where public_id = _session.project_id
       and valid_range @> current_timestamp;

    select history_id into strict new.target_hst_id
      from target_ssh_hst
     where public_id = _session.target_id
       and valid_range @> current_timestamp;

    select * into _host
      from host
     where public_id = (select host_id
                          from session_host_set_host
                         where session_id = _session.public_id);

      case when found then
        select history_id into strict new.host_hst_id
          from (
            select history_id
              from static_host_hst
             where public_id = _host.public_id
               and valid_range @> current_timestamp
             union
            select history_id
              from host_plugin_host_hst
             where public_id = _host.public_id
               and valid_range @> current_timestamp
            ) as h;
        select history_id into strict new.host_catalog_hst_id
          from (
            select history_id
              from static_host_catalog_hst
             where public_id = _host.catalog_id
               and valid_range @> current_timestamp
             union
            select history_id
              from host_plugin_catalog_hst
             where public_id = _host.catalog_id
               and valid_range @> current_timestamp
            ) as h;
      else
        select history_id into strict new.host_hst_id
          from no_host_history;
        select history_id into strict new.host_catalog_hst_id
          from no_host_catalog_history;
      end case;

    return new;
  end;
  $$ language plpgsql;
  comment on function insert_session_recording is
    'insert_session_recording is a before insert trigger for the recording_session table.';

  create trigger insert_session_recording before insert on recording_session
    for each row execute procedure insert_session_recording();

  create function update_session_recording() returns trigger
  as $$
  begin
    if new.state != old.state and old.state != 'started' then
      raise exception 'state can only be updated once';
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function update_session_recording is
    'update_session_recording is a before update trigger for the recording_session table.';

  create trigger update_session_recording before update on recording_session
    for each row execute procedure update_session_recording();

  create table recording_connection (
    public_id wt_public_id primary key,
    session_id wt_public_id null, -- Can be null if associated session has been deleted
    session_connection_id wt_public_id null -- Can be null if associated connection has been deleted
      constraint recording_connection_session_connection_id_uq unique,
    recording_session_id wt_public_id not null,
    create_time wt_timestamp not null,
    update_time wt_timestamp not null,
    start_time rec_timestamp null, -- When the connection recording was started in the worker
    -- When the connection recording ended in the worker
    -- Guaranteed to be recorded monotonically relative to start_time.
    end_time rec_timestamp null
      constraint end_time_null_or_after_start_time
        check (end_time > start_time),
    -- Need to be nullable as we only know them when the connection is closed.
    bytes_up bigint null
      constraint bytes_up_null_zero_or_positive
        check (bytes_up >= 0),
    bytes_down bigint null
      constraint bytes_down_null_zero_or_positive
        check (bytes_down >= 0),
    constraint session_connection_fkey
      foreign key (session_id, session_connection_id)
      references session_connection (session_id, public_id)
      on delete set null -- Set both IDs null if associated connection/session is deleted
      on update cascade,
    constraint recording_session_fkey1
      foreign key (session_id, recording_session_id)
      references recording_session (session_id, public_id)
      on delete cascade -- Note that this doesn't actually cascade deletes from recording_session
      on update cascade,
    constraint recording_session_fkey2
      foreign key (recording_session_id)
      references recording_session (public_id)
      on delete cascade -- Cascade deletes from recording_session
      on update cascade
  );
  comment on table recording_connection is
    'recording_connection holds metadata for a recorded connection. It outlives the connection itself. '
    'It belongs to exactly one recording_session';

  create trigger update_time_column before update on recording_connection
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on recording_connection
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on recording_connection
    for each row execute procedure immutable_columns('public_id', 'recording_session_id', 'create_time');

  create trigger set_once_columns before update on recording_connection
    for each row execute procedure set_once_columns('start_time', 'end_time', 'bytes_up', 'bytes_down');

  create function check_session_id_and_session_connection_id_not_null() returns trigger
  as $$
  begin
    if new.session_id is null then
      raise exception 'a new recorded connection must have a session_id';
    end if;
    if new.session_connection_id is null then
      raise exception 'a new recorded connection must have a session_connection_id';
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function check_session_id_and_session_connection_id_not_null is
    'check_session_id_and_session_connection_id_not_null ensures that new recorded connections have a session and session connection associated with them.';

  create trigger check_session_id_and_session_connection_id_not_null before insert on recording_connection
    for each row execute procedure check_session_id_and_session_connection_id_not_null();

  create table recording_channel (
    public_id wt_public_id primary key,
    recording_connection_id wt_public_id not null
      constraint recording_connection_fkey
        references recording_connection (public_id)
        on delete cascade
        on update cascade,
    constraint recording_channel_recording_connection_id_public_id_uq
      unique (recording_connection_id, public_id)
  );
  comment on table recording_channel is
    'recording_channel is a base table for recorded channel types. It belongs to exactly one recording_connection';

  create trigger immutable_columns before update on recording_channel
    for each row execute procedure immutable_columns('public_id', 'recording_connection_id');

  create function insert_recording_channel_subtype() returns trigger
  as $$
  begin
    insert into recording_channel
      (public_id, recording_connection_id)
    values
      (new.public_id, new.recording_connection_id);
    return new;
  end;
  $$ language plpgsql;
  comment on function insert_recording_channel_subtype is
    'insert_recording_channel_subtype inserts a row into the base table when a row is inserted into a subtype table.';

  create function delete_recording_channel_subtype() returns trigger
  as $$
  begin
    delete
      from recording_channel
     where public_id = old.public_id;
    return null; -- result is ignored since this is an after trigger
  end;
  $$ language plpgsql;
  comment on function delete_recording_channel_subtype is
    'delete_recording_channel_subtype deletes a row from the base table when a row is deleted in a subtype table.';


  -- Channel types reference: https://www.rfc-editor.org/rfc/rfc4250.html#section-4.9.1
  create table recording_channel_ssh_channel_type_enm (
    name text primary key
      constraint only_predefined_channel_types_allowed
        check(name in ('unknown', 'session', 'x11', 'forwarded-tcpip', 'direct-tcpip'))
  );
  comment on table recording_channel_ssh_channel_type_enm is
    'recording_channel_ssh_channel_type_enm holds valid values for the channel_type of a recording_channel_ssh row. '
    'Some known channel types are defined in https://www.rfc-editor.org/rfc/rfc4250.html#section-4.9.1';

  insert into recording_channel_ssh_channel_type_enm (name)
  values
    ('unknown'),
    ('session'),
    ('x11'),
    ('forwarded-tcpip'),
    ('direct-tcpip');

  create trigger immutable_columns before update on recording_channel_ssh_channel_type_enm
    for each row execute procedure immutable_columns('name');

  create table recording_channel_ssh (
    public_id wt_public_id primary key,
    recording_connection_id wt_public_id not null,
    create_time wt_timestamp not null,
    update_time wt_timestamp not null,
    start_time rec_timestamp not null, -- When the channel recording was started in the worker
    -- When the channel recording ended in the worker
    -- Guaranteed to be recorded monotonically relative to start_time.
    end_time rec_timestamp not null
      constraint end_time_after_start_time
        check (end_time > start_time),
    bytes_up bigint not null
      constraint bytes_up_zero_or_positive
        check (bytes_up >= 0),
    bytes_down bigint not null
      constraint bytes_down_zero_or_positive
        check (bytes_down >= 0),
    channel_type text not null
      constraint recording_channel_ssh_channel_type_enm_fkey
        references recording_channel_ssh_channel_type_enm (name)
        on delete restrict
        on update cascade,
    constraint recording_channel_fkey
      foreign key (public_id, recording_connection_id)
        references recording_channel (public_id, recording_connection_id)
        on delete cascade
        on update cascade
  );
  comment on table recording_channel_ssh is
    'recording_channel_ssh is a subtype table for a recorded ssh channel. It belongs to exactly one recording_connection';

  create trigger update_time_column before update on recording_channel_ssh
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on recording_channel_ssh
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on recording_channel_ssh
    for each row execute procedure immutable_columns('public_id', 'recording_connection_id', 'create_time', 'start_time', 'end_time', 'bytes_up', 'bytes_down', 'channel_type');

  create trigger insert_recording_channel_subtype before insert on recording_channel_ssh
    for each row execute procedure insert_recording_channel_subtype();

  create trigger delete_recording_channel_subtype after delete on recording_channel_ssh
    for each row execute procedure delete_recording_channel_subtype();

  create function validate_recording_channel_ssh_insert(new_channel_type text, new_public_id text) returns void
  as $$
  begin
    -- If the channel type is session, the program table must have exactly 1 entry matching this row
    if new_channel_type = 'session' then
      if count(*) != 1 from recording_channel_ssh_session_channel where recording_channel_id = new_public_id then
        raise exception 'Channel recording of type ''session'' must populate recording_channel_ssh_session_channel';
      end if;
    end if;
  end;
  $$ language plpgsql;
  comment on function validate_recording_channel_ssh_insert is 
    'function used to ensure each recording_channel_ssh entry with channel_type session has an associated '
    'entry in recording_channel_ssh_session_channel.';

  create function insert_recording_channel_ssh() returns trigger 
  as $$
  begin
    perform validate_recording_channel_ssh_insert(new.channel_type, new.public_id);
    return null;
  end;
  $$ language plpgsql;
  comment on function insert_recording_channel_ssh() is 
    'function used on recording_channel_ssh after insert initially deferred to ensure each '
    'entry with a channel_type of ''session'' has an associated entry in recording_channel_ssh_session_channel';

  create constraint trigger insert_recording_channel_ssh
    after insert on recording_channel_ssh deferrable initially deferred 
    for each row execute procedure insert_recording_channel_ssh();


  create table recording_channel_ssh_session_channel_program_enm (
    name text primary key
      constraint only_predefined_programs_allowed
        check(name in ('none', 'shell', 'exec', 'subsystem'))
  );
  comment on table recording_channel_ssh_session_channel_program_enm is
    'recording_channel_ssh_session_channel_program_enm holds valid values for the program column in recording_channel_ssh_session_channel';

  insert into recording_channel_ssh_session_channel_program_enm (name)
  values
    ('none'),
    ('shell'),
    ('exec'),
    ('subsystem');

  create trigger immutable_columns before update on recording_channel_ssh_session_channel_program_enm
    for each row execute procedure immutable_columns('name');

  create table recording_channel_ssh_session_channel (
    recording_channel_id wt_public_id primary key
      constraint recording_channel_ssh_fkey
        references recording_channel_ssh (public_id)
        on delete cascade
        on update cascade,
    program text not null
      constraint recording_channel_ssh_session_channel_program_enm_fkey
        references recording_channel_ssh_session_channel_program_enm (name)
        on delete restrict
        on update cascade
  );

  create trigger immutable_columns before update on recording_channel_ssh_session_channel
    for each row execute procedure immutable_columns('recording_channel_id', 'program');

  create function validate_recording_channel_ssh_session_channel_insert(new_recording_channel_id text, new_program text) returns void
  as $$
  begin
    -- First check that the channel_type is session in the channel recording table
    if channel_type != 'session' from recording_channel_ssh where public_id = new_recording_channel_id then
      raise exception 'Session channel must have channel_type ''session''';
    end if;
    -- If the program is subsystem, the subsystem table must have exactly 1 entry matching this row
    if new_program = 'subsystem' then
      if count(*) != 1 from recording_channel_ssh_session_channel_program_subsystem where recording_channel_id = new_recording_channel_id then
        raise exception 'Session channel with program ''subsystem'' must populate recording_channel_ssh_session_channel_program_subsystem';
      end if;
    end if;
    -- If the program is exec, the exec table must have exactly 1 entry matching this row
    if new_program = 'exec' then
      if count(*) != 1 from recording_channel_ssh_session_channel_program_exec where recording_channel_id = new_recording_channel_id then
        raise exception 'Session channel with program ''exec'' must populate recording_channel_ssh_session_channel_program_exec';
      end if;
    end if;
  end;
  $$ language plpgsql;
  comment on function validate_recording_channel_ssh_session_channel_insert is 
    'function used to ensure each recording_channel_ssh_session_channel entry has an associated '
    'entry in recording_channel_ssh with a channel_type of ''session''.';

  create function insert_recording_channel_ssh_session_channel() returns trigger 
  as $$
  begin
    perform validate_recording_channel_ssh_session_channel_insert(new.recording_channel_id, new.program);
    return null;
  end;
  $$ language plpgsql;
  comment on function insert_recording_channel_ssh_session_channel() is 
    'function used on recording_channel_ssh_session_channel after insert initially deferred to '
    'validate inserts.';

  create constraint trigger insert_recording_channel_ssh_session_channel
    after insert on recording_channel_ssh_session_channel deferrable initially deferred 
    for each row execute procedure insert_recording_channel_ssh_session_channel();


  create table recording_channel_ssh_session_channel_program_subsystem (
    recording_channel_id wt_public_id primary key
      constraint recording_channel_ssh_session_channel_fkey
        references recording_channel_ssh_session_channel (recording_channel_id)
        on delete cascade
        on update cascade,
    -- https://www.rfc-editor.org/rfc/rfc4250.html#section-4.6.1 defines
    -- this as <= 64 bytes. Lets use a larger number just in case.
    subsystem_name text not null
      constraint subsystem_lte_1024_bytes
        check(length(subsystem_name) <= 1024)
  );

  create trigger immutable_columns before update on recording_channel_ssh_session_channel_program_subsystem
    for each row execute procedure immutable_columns('recording_channel_id', 'subsystem_name');

  create function validate_recording_channel_ssh_subsystem_insert(new_recording_channel_id text) returns void
  as $$
  begin
    if program != 'subsystem' from recording_channel_ssh_session_channel where recording_channel_id = new_recording_channel_id then
      raise exception 'Session channel subsystem program must have program ''subsystem''';
    end if;
  end;
  $$ language plpgsql;
  comment on function validate_recording_channel_ssh_subsystem_insert is 
    'function used to ensure each recording_channel_ssh_session_channel_program_subsystem entry has an associated '
    'entry in recording_channel_ssh_session_channel with a program of ''subsystem''.';

  create function insert_recording_channel_ssh_session_channel_program_subsystem() returns trigger 
  as $$
  begin
    perform validate_recording_channel_ssh_subsystem_insert(new.recording_channel_id);
    return null;
  end;
  $$ language plpgsql;
  comment on function insert_recording_channel_ssh_session_channel_program_subsystem() is 
  'function used on recording_channel_ssh_session_channel_program_subsystem after insert initially deferred to ensure each '
  'entry has an associated entry in recording_channel_ssh_session_channel with a program of ''subsystem''';

  create constraint trigger insert_recording_channel_ssh_session_channel_program_subsystem
    after insert on recording_channel_ssh_session_channel_program_subsystem deferrable initially deferred 
    for each row execute procedure insert_recording_channel_ssh_session_channel_program_subsystem();


  create table recording_channel_ssh_session_channel_program_exec_enm (
    name text primary key
      constraint only_predefined_execs_allowed
        check(name in ('unknown', 'scp', 'rsync'))
  );
  comment on table recording_channel_ssh_session_channel_program_exec_enm is
    'recording_channel_ssh_session_channel_program_exec_enm holds valid values for the exec_program column in recording_channel_ssh_session_channel_program_exec';

  insert into recording_channel_ssh_session_channel_program_exec_enm (name)
  values
    ('unknown'),
    ('scp'),
    ('rsync');

  create trigger immutable_columns before update on recording_channel_ssh_session_channel_program_exec_enm
    for each row execute procedure immutable_columns('name');

  create table recording_channel_ssh_session_channel_program_exec (
    recording_channel_id wt_public_id primary key
      constraint recording_channel_ssh_session_channel_fkey
        references recording_channel_ssh_session_channel (recording_channel_id)
        on delete cascade
        on update cascade,
    exec_program text not null
      constraint recording_channel_ssh_session_channel_program_exec_enm_fkey
        references recording_channel_ssh_session_channel_program_exec_enm (name)
        on delete restrict
        on update cascade
  );

  create trigger immutable_columns before update on recording_channel_ssh_session_channel_program_exec
    for each row execute procedure immutable_columns('recording_channel_id');

  create function validate_recording_channel_ssh_exec_insert(new_recording_channel_id text) returns void
  as $$
  begin
    if program != 'exec' from recording_channel_ssh_session_channel where recording_channel_id = new_recording_channel_id then
      raise exception 'Session channel exec program must have program ''exec''';
    end if;
  end;
  $$ language plpgsql;
  comment on function validate_recording_channel_ssh_exec_insert is 
    'function used to ensure each recording_channel_ssh_session_channel_program_exec entry has an associated '
    'entry in recording_channel_ssh_session_channel with a program of ''exec''.';

  create function insert_recording_channel_ssh_session_channel_program_exec() returns trigger 
  as $$
  begin
    perform validate_recording_channel_ssh_exec_insert(new.recording_channel_id);
    return null;
  end;
  $$ language plpgsql;
  comment on function insert_recording_channel_ssh_session_channel_program_exec() is 
    'function used on recording_channel_ssh_session_channel_program_exec after insert initially deferred to ensure each '
    'entry has an associated entry in recording_channel_ssh_session_channel with a program of ''exec''';

  create constraint trigger insert_recording_channel_ssh_session_channel_program_exec
    after insert on recording_channel_ssh_session_channel_program_exec deferrable initially deferred 
    for each row execute procedure insert_recording_channel_ssh_session_channel_program_exec();
  
commit;
