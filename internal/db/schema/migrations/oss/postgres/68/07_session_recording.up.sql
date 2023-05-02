-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

  create domain rec_timestamp as timestamptz default null;
  comment on domain rec_timestamp is
    'a nullable timestamp with a time zone used for start and end times of recordings';


  create table recording_session (
    public_id wt_public_id primary key,
    storage_bucket_id wt_public_id not null
      constraint storage_bucket_fkey
        references storage_bucket (public_id)
        on delete restrict -- Storage buckets with session recordings cannot be deleted
        on update cascade,
    session_id wt_public_id null -- Can be null if associated session has been deleted
      constraint session_fkey
        references session (public_id)
        on delete set null -- Set null if associated session is deleted
        on update cascade
      constraint recording_session_session_id_uq unique,
    create_time wt_timestamp not null,
    update_time wt_timestamp not null,
    start_time rec_timestamp null, -- When the session recording was started in the worker
    -- When the session recording ended in the worker
    -- Guaranteed to be recorded monotonically relative to start_time.
    end_time rec_timestamp null
      constraint end_time_null_or_after_start_time
        check (end_time > start_time),
    constraint recording_session_session_id_public_id_uq
      unique (session_id, public_id)
  );
  comment on table recording_session is
    'recording_session holds metadata for the recording of a session. It outlives the session itself.';

  create trigger update_time_column before update on recording_session
    for each row execute procedure update_time_column();

  create trigger default_create_time_column before insert on recording_session
    for each row execute procedure default_create_time();

  create trigger immutable_columns before update on recording_session
    for each row execute procedure immutable_columns('public_id', 'storage_bucket_id', 'create_time');
  
  create trigger set_once_columns before update on recording_session
    for each row execute procedure set_once_columns('start_time', 'end_time');

  create function check_session_id_not_null() returns trigger
  as $$
  begin
    if new.session_id is null then
      raise exception 'a new recorded session must have a session_id';
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function check_session_id_not_null is
    'check_session_id_not_null ensures that new recorded sessions have a session associated with them.';

  create trigger check_session_id_not_null before insert on recording_session
    for each row execute procedure check_session_id_not_null();

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


  -- TODO: We currently only include the channel type here,
  -- but it's not enough on its own to determine what mime types
  -- are supported by a channel. We'll need extra information in
  -- the schema for this, but it's not clear what yet.
  -- Channel types reference: https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xml#ssh-parameters-11
  create table recording_channel_ssh_channel_type_enm (
    name text primary key
      constraint only_predefined_channel_types_allowed
        check(name in ('unknown', 'session', 'x11', 'forwarded-tcpip', 'direct-tcpip'))
  );
  comment on table recording_channel_ssh_channel_type_enm is
    'recording_channel_ssh_channel_type_enm holds valid values for the channel_type of a recording_channel_ssh row. '
    'Some known channel types are defined in https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xml#ssh-parameters-11';

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

commit;
