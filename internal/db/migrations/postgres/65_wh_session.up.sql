begin;

/*
  Dimensions are:
  -[x] date, time,
  -[x] target, host, host_set, host_catalog,
  -[x] user, auth_token,

  -[ ] worker,
  -[ ] address, port,
*/

  create table wh_host_dimension (
    id                            bigint generated always as identity primary key,

    host_id                       wt_public_id not null,
    host_type                     text not null,
    host_name                     text not null,
    host_description              text not null,
    host_address                  text not null,

    host_set_id                   wt_public_id not null,
    host_set_type                 text not null,
    host_set_name                 text not null,
    host_set_description          text not null,

    host_catalog_id               wt_public_id not null,
    host_catalog_type             text not null,
    host_catalog_name             text not null,
    host_catalog_description      text not null,

    target_id                     wt_public_id not null,
    target_name                   text not null,
    target_description            text not null,

    project_id                    wt_public_id not null,
    project_name                  text not null,
    project_description           text not null,

    host_organization_id          wt_public_id not null,
    host_organization_name        text not null,
    host_organization_description text not null,

    current_row_indicator         text not null,
    row_effective_time            wt_timestamp,
    row_expiration_time           wt_timestamp
  );
  -- TODO(mgaffney) 09/2020: insert 0 row

  create table wh_user_dimension (
    id                            bigint generated always as identity primary key,

    user_id                       wt_public_id not null,
    user_name                     text not null,
    user_description              text not null,

    auth_account_id               wt_public_id not null,
    auth_account_type             text not null,
    auth_account_name             text not null,
    auth_account_description      text not null,

    auth_method_id                wt_public_id not null,
    auth_method_type              text not null,
    auth_method_name              text not null,
    auth_method_description       text not null,

    user_organization_id          wt_public_id not null,
    user_organization_name        text not null,
    user_organization_description text not null,

    current_row_indicator         text not null,
    row_effective_time            wt_timestamp,
    row_expiration_time           wt_timestamp
  );
  -- TODO(mgaffney) 09/2020: insert 0 row

  -- The wh_session_accumulating_fact table is an accumulating snapshot.
  -- The grain of the fact table is one row per session.
  create table wh_session_accumulating_fact (
    -- TODO(mgaffney) 09/2020: partion table

    -- auth token id is a degenerate dimension
    auth_token_id wt_public_id not null,
    -- foreign keys to the dimension tables
    host_id bigint not null
      references wh_host_dimension (id)
      on delete restrict
      on update cascade,
    user_id bigint not null
      references wh_user_dimension (id)
      on delete restrict
      on update cascade,
    -- date and time foreign keys
    session_pending_date_key integer not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    session_pending_time_key integer not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    session_connected_date_key integer not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    session_connected_time_key integer not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    session_canceling_date_key integer not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    session_canceling_time_key integer not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    session_closed_date_key integer not null
      references wh_date_dimension (id)
      on delete restrict
      on update cascade,
    session_closed_time_key integer not null
      references wh_time_of_day_dimension (id)
      on delete restrict
      on update cascade,
    session_pending_time timestamp with time zone not null,
    session_connected_time timestamp with time zone,
    session_canceling_time timestamp with time zone,
    session_closed_time timestamp with time zone,

    -- The client address is a degenerate dimension
    client_address inet not null,
    -- The target address and port are degenerate dimensions
    target_address inet not null,
    target_port integer
      not null
      check(
        target_port > 0
        and
        target_port <= 65535
      ),

    -- the total number of bytes received by the worker from the user and sent
    -- to the host for this session
    bytes_up bigint -- can be null
      check (
        bytes_up is null
        or
        bytes_up >= 0
      ),
    -- the total number of bytes received by the worker from the host and sent
    -- to the user for this session
    bytes_down bigint -- can be null
      check (
        bytes_down is null
        or
        bytes_down >= 0
      )
  );

commit;
