-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create function wt_add_days(ds integer, ts timestamptz) returns timestamptz
  as $$
  select ts + ds * '1 day'::interval;
  $$ language sql
    stable
    returns null on null input;
  comment on function wt_add_days is
    'wt_add_days returns ts + days.';

  alter table recording_session add column retain_for_days int not null default -1;
  alter table recording_session add column retain_until rec_timestamp;

  alter table recording_session add column delete_after_days int not null default 0
    constraint delete_after_days_non_negative
    check(delete_after_days >= 0);
  
  alter table recording_session
    add constraint delete_after_days_greater_or_equal_than_retain_for_days
    check(delete_after_days >= retain_for_days or delete_after_days = 0);

  alter table recording_session add column delete_after rec_timestamp
    constraint delete_after_null_or_after_retain_until
    check(delete_after is null or delete_after >= retain_until);

  alter table recording_session add column delete_time rec_timestamp
    constraint delete_time_null_or_after_retain_until
    check(delete_time is null or delete_time >= retain_until);

  alter table recording_session add column target_org_id wt_public_id null
    references iam_scope_org(scope_id)
    on delete set null
    on update cascade;

  -- set_delete_and_retain_times is a trigger that runs before update on recording_session
  -- to set the calculated timestamps for retain_until and delete_after from the session's
  -- end time.
  create or replace function set_delete_and_retain_times() returns trigger
  as $$
  begin
    if new.end_time is not null then
      if new.retain_for_days = 0 then
        new.retain_until = null;
      elsif new.retain_for_days < 0 then
        new.retain_until = 'infinity'::timestamptz;
      else
        new.retain_until = wt_add_days(new.retain_for_days, new.end_time);
      end if;

      if new.delete_after_days = 0 then
        new.delete_after = null;
      -- new.delete_after_days < 0 is not possible due to delete_after_days_non_negative
      else
        new.delete_after = wt_add_days(new.delete_after_days, new.end_time);
      end if;
    end if;

    return new;
  end;
    $$ language plpgsql;

  create trigger retain_for_days_and_delete_after_days_not_zero before insert or update on recording_session
    for each row execute procedure retain_for_days_and_delete_after_days_not_zero();

  create trigger delete_after_days_zero_if_infinite_retain_for_days before insert or update on recording_session
    for each row execute procedure delete_after_days_zero_if_infinite_retain_for_days();

  create trigger set_delete_and_retain_times before update on recording_session
    for each row execute procedure set_delete_and_retain_times();

  -- target_org_id must be populated
  update recording_session rs
  set target_org_id = ish.parent_id
  from iam_scope_hst ish
    join iam_scope_org iso on ish.parent_id = iso.scope_id
  where ish.history_id = rs.target_project_hst_id;

  -- replaces 71/12_session_recording_views.up.sql
  -- replaced by 92/01_host_plugin_catalog_worker_filter.up.sql
  drop view session_recording_aggregate;  -- this is necessary, throws weird syntax error without
  create view session_recording_aggregate as
    select
      rs.public_id,
      rs.storage_bucket_id,
      rs.session_id,
      rs.create_time,
      rs.update_time,
      rs.start_time,
      rs.end_time,
      rs.state,
      rs.error_details,
      rs.endpoint,
      rs.retain_until,
      rs.delete_after,
      rs.target_org_id,
      sb.scope_id as storage_bucket_scope_id,
      -- fields that cover the user fields at creation time
      uh.public_id as user_history_public_id,
      uh.name as user_history_name,
      uh.description as user_history_description,
      uh.scope_id as user_history_scope_id,
      -- fields that cover the user's scope information at creation time
      ush.public_id as user_scope_history_public_id,
      ush.name as user_scope_history_name,
      ush.description as user_scope_history_description,
      ush.type as user_scope_history_type,
      ush.parent_id as user_scope_history_parent_id,
      ush.primary_auth_method_id as user_scope_history_primary_auth_method_id,
      -- fields that cover the target fields at creation time
      th.public_id as target_history_public_id,
      th.name as target_history_name,
      th.description as target_history_description,
      th.default_port as target_history_default_port,
      th.session_max_seconds as target_history_session_max_seconds,
      th.session_connection_limit as target_history_session_connection_limit,
      th.worker_filter as target_history_worker_filter,
      th.ingress_worker_filter as target_history_ingress_worker_filter,
      th.egress_worker_filter as target_history_egress_worker_filter,
      th.default_client_port as target_history_default_client_port,
      th.enable_session_recording as target_history_enable_session_recording,
      th.storage_bucket_id as target_history_storage_bucket_id,
      -- fields that cover the target's scope information at creation time
      tsh.public_id as target_scope_history_public_id,
      tsh.name as target_scope_history_name,
      tsh.description as target_scope_history_description,
      tsh.type as target_scope_history_type,
      tsh.parent_id as target_scope_history_parent_id,
      tsh.primary_auth_method_id as target_scope_history_primary_auth_method_id,
      -- static
      -- host catalogs
      shch.public_id as static_catalog_history_public_id,
      shch.project_id as static_catalog_history_project_id,
      shch.name as static_catalog_history_name,
      shch.description as static_catalog_history_description,
      -- hosts
      shh.public_id as static_host_history_public_id,
      shh.name as static_host_history_name,
      shh.description as static_host_history_description,
      -- catalog_id is unnecessary as its inferred from the host catalog row
      shh.address as static_host_history_address,

      -- plugin
      -- host catalogs
      hpch.public_id as plugin_catalog_history_public_id,
      hpch.project_id as plugin_catalog_history_project_id,
      hpch.name as plugin_catalog_history_name,
      hpch.description as plugin_catalog_history_description,
      hpch.attributes as plugin_catalog_history_attributes,
      hpch.plugin_id as plugin_catalog_history_plugin_id,
      -- hosts
      hph.public_id as plugin_host_history_public_id,
      hph.name as plugin_host_history_name,
      hph.description as plugin_host_history_description,
      -- catalog_id is unnecessary as its inferred from the host catalog row
      hph.external_id as plugin_host_history_external_id,
      hph.external_name as plugin_host_history_external_name

    from recording_session rs
    join storage_plugin_storage_bucket sb on
      rs.storage_bucket_id = sb.public_id
    join iam_user_hst uh on
      rs.user_hst_id = uh.history_id
    join iam_scope_hst as ush on
      rs.user_scope_hst_id = ush.history_id
    join target_ssh_hst th on
      rs.target_hst_id = th.history_id
    join iam_scope_hst as tsh on
      rs.target_project_hst_id = tsh.history_id
    left join static_host_catalog_hst as shch on
      rs.host_catalog_hst_id = shch.history_id
    left join host_plugin_catalog_hst as hpch on
      rs.host_catalog_hst_id = hpch.history_id
    left join static_host_hst as shh on
      rs.host_hst_id = shh.history_id
    left join host_plugin_host_hst as hph on
      rs.host_hst_id = hph.history_id
    where (rs.delete_after is null or rs.delete_after > now())
      and (rs.delete_time is null or rs.delete_time > now());
  comment on view session_recording_aggregate is
    'session_recording_aggregate contains the session recording resource with its storage bucket scope info and historical user info.';

  -- Update the indexes used for listing recordings to include the delete time and delete after,
  -- since they're now used in the query.
  drop index recording_session_create_time_public_id_idx;
  drop index recording_session_update_time_public_id_idx;

  create index recording_session_create_time_public_id_delete_time_delete_idx
      on recording_session (create_time desc, public_id desc, delete_time, delete_after);
  create index recording_session_update_time_public_id_delete_time_delete_idx
      on recording_session (update_time desc, public_id desc, delete_time, delete_after);

  analyze recording_session;

commit;
