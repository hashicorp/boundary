-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Column names for numeric fields that are not a measurement end in id or
  -- number. This naming convention enables automatic field type detection in
  -- certain data analysis tools.
  -- https://help.tableau.com/current/pro/desktop/en-us/data_clean_adm.htm

  -- The wh_session_accumulating_fact table is an accumulating snapshot.
  -- The table wh_session_accumulating_fact is an accumulating fact table.
  -- The grain of the fact table is one row per session.
  create table wh_session_accumulating_fact (
    session_id wt_public_id primary key,
    -- auth token id is a degenerate dimension
    auth_token_id wt_public_id not null,

    -- foreign keys to the dimension tables
    host_id wh_dim_id not null
      references wh_host_dimension (id)
      on delete restrict
      on update cascade,
    user_id wh_dim_id not null
      references wh_user_dimension (id)
      on delete restrict
      on update cascade,

    -- TODO(mgaffney) 09/2020: add dimension and foreign key for the session
    -- termination reason

    -- date and time foreign keys
    session_pending_date_id integer not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    session_pending_time_id integer not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    session_pending_time wh_timestamp,

    session_active_date_id integer default -1 not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    session_active_time_id integer default -1 not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    session_active_time wh_timestamp default 'infinity'::timestamptz,

    session_canceling_date_id integer default -1 not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    session_canceling_time_id integer default -1 not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    session_canceling_time wh_timestamp default 'infinity'::timestamptz,

    session_terminated_date_id integer default -1 not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    session_terminated_time_id integer default -1 not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    session_terminated_time wh_timestamp default 'infinity'::timestamptz,

    -- TODO(mgaffney) 09/2020: add columns for session expiration

    -- TODO(mgaffney) 09/2020: add connection limit. This may need a dimension
    -- table and foreign key column to represent unlimited connections.

    -- The total number of connections made during the session.
    total_connection_count bigint, -- will be null until the first connection is created

    -- The total number of bytes received by workers from the client and sent
    -- to the endpoint for this session.
    -- total_bytes_up is a fully additive measurement.
    total_bytes_up wh_bytes_transmitted, -- will be null until the first connection is closed
    -- The total number of bytes received by workers from the endpoint and sent
    -- to the client for this session.
    -- total_bytes_down is a fully additive measurement.
    total_bytes_down wh_bytes_transmitted -- will be null until the first connection is closed
  );

  -- The wh_session_connection_accumulating_fact table is an accumulating fact table.
  -- The grain of the fact table is one row per session connection.
  create table wh_session_connection_accumulating_fact  (
    connection_id wt_public_id primary key,
    -- session_id is a degenerate dimension
    session_id wt_public_id not null
      references wh_session_accumulating_fact (session_id)
      on delete cascade
      on update cascade,

    -- foreign keys to the dimension tables
    host_id wh_dim_id not null
      references wh_host_dimension (id)
      on delete restrict
      on update cascade,
    user_id wh_dim_id not null
      references wh_user_dimension (id)
      on delete restrict
      on update cascade,

    -- TODO(mgaffney) 09/2020: add dimension and foreign key for the connection
    -- closed reason

    -- date and time foreign keys and timestamps
    connection_authorized_date_id integer not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    connection_authorized_time_id integer not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    connection_authorized_time wh_timestamp,

    connection_connected_date_id integer default -1 not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    connection_connected_time_id integer default -1 not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    connection_connected_time wh_timestamp default 'infinity'::timestamptz,

    connection_closed_date_id integer default -1 not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    connection_closed_time_id integer default -1 not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    connection_closed_time wh_timestamp default 'infinity'::timestamptz,

    -- TODO(mgaffney) 09/2020: add a connection_duration_in_seconds column

    -- The client address and port are degenerate dimensions
    client_tcp_address inet, -- can be null
    client_tcp_port_number wh_inet_port, -- can be null

    -- The endpoint address and port are degenerate dimensions
    endpoint_tcp_address inet, -- can be null
    endpoint_tcp_port_number wh_inet_port, -- can be null

    -- the connection_count must always be 1
    -- this is a common pattern in data warehouse models
    -- See The Data Warehouse Toolkit, Third Edition
    -- by Ralph Kimball and Margy Ross for more information
    connection_count smallint default 1 not null
      constraint connection_count_must_be_1
      check(connection_count = 1),

    -- The total number of bytes received by the worker from the client and sent
    -- to the endpoint for this connection.
    -- bytes_up is a fully additive measurement.
    bytes_up wh_bytes_transmitted, -- can be null
    -- The total number of bytes received by the worker from the endpoint and sent
    -- to the client for this connection.
    -- bytes_down is a fully additive measurement.
    bytes_down wh_bytes_transmitted -- can be null
  );

  -- TODO(mgaffney) 09/2020: Research and test if the comment fields are used by
  -- data analysis tools.
  comment on table wh_session_connection_accumulating_fact is
    'The Wh Session Connection Accumulating Fact table is an accumulating fact table. '
    'The grain of the fact table is one row per session connection.';
  comment on column wh_session_connection_accumulating_fact.bytes_up is
    'Bytes Up is the total number of bytes received by the worker from the '
    'client and sent to the endpoint for this connection. Bytes Up is a fully '
    'additive measurement.';
  comment on column wh_session_connection_accumulating_fact.bytes_down is
    'Bytes Down is the total number of bytes received by the worker from the '
    'endpoint and sent to the client for this connection. Bytes Down is a fully '
    'additive measurement.';

  create index on wh_session_connection_accumulating_fact(session_id);

commit;
