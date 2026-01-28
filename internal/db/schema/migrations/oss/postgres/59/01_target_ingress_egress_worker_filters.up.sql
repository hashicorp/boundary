-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Update tables to add ingress_worker_filter and egress_worker_filter
alter table session
  add column egress_worker_filter wt_bexprfilter,
  add column ingress_worker_filter wt_bexprfilter;

alter table target_tcp
  add column egress_worker_filter wt_bexprfilter,
  add column ingress_worker_filter wt_bexprfilter;

-- Trigger functions to ensure that worker_filter and ingress/egress_worker_filter are mutually exclusive
-- and that worker_filter can only be updated
create function validate_filter_values_on_insert() returns trigger
as $$
begin
  if new.worker_filter is not null then
    raise exception 'worker_filter is deprecated and cannot be set';
  end if;

  return new;

end;
$$ language plpgsql;

create function validate_filter_values_on_update() returns trigger
as $$
begin
  if new.egress_worker_filter is not null then
    if new.worker_filter = old.worker_filter then
      new.worker_filter = null;
    end if;
  end if;

  if new.ingress_worker_filter is not null then
    if new.worker_filter = old.worker_filter then
      new.worker_filter = null;
    end if;
  end if;

  if new.worker_filter is not null then
-- New worker_filter values are only allowed as an update to support users with existing worker_filter values
    if old.worker_filter is null then
      raise exception 'worker_filter is deprecated and cannot be set';
    end if;

    if new.egress_worker_filter is not null then
      raise exception 'cannot set worker_filter and egress_filter; they are mutually exclusive fields';
    end if;

    if new.ingress_worker_filter is not null then
      raise exception 'cannot set worker_filter and ingress_filter; they are mutually exclusive fields';
    end if;
  end if;

  return new;

end;
$$ language plpgsql;

create trigger update_tcp_target_filter_validate before update on target_tcp
  for each row execute procedure validate_filter_values_on_update();

create trigger insert_tcp_target_filter_validate before insert on target_tcp
  for each row execute procedure validate_filter_values_on_insert();

-- Update views
-- Dropping dependent views first, from views in 44/03_targets.up.sql
drop view whx_credential_dimension_source;
drop view whx_host_dimension_source;

-- Replaces target_all_subtypes defined in 44/03_targets.up.sql
drop view target_all_subtypes;
create view target_all_subtypes as
select public_id,
   project_id,
   name,
   description,
   default_port,
   session_max_seconds,
   session_connection_limit,
   version,
   create_time,
   update_time,
   worker_filter,
   egress_worker_filter,
   ingress_worker_filter,
   'tcp' as type
from target_tcp;

-- Replaces view from 56/06_add_session_private_key_column.up.sql
-- Replaced in 60/02_sessions.up.sql
drop view session_list;
create view session_list as
select
  s.public_id,
  s.user_id,
  s.host_id,
  s.target_id,
  s.host_set_id,
  s.auth_token_id,
  s.project_id,
  s.certificate,
  s.certificate_private_key,
  s.expiration_time,
  s.connection_limit,
  s.tofu_token,
  s.key_id,
  s.termination_reason,
  s.version,
  s.create_time,
  s.update_time,
  s.endpoint,
  s.worker_filter,
  s.egress_worker_filter,
  s.ingress_worker_filter,
  ss.state,
  ss.previous_end_time,
  ss.start_time,
  ss.end_time,
  sc.public_id as connection_id,
  sc.client_tcp_address,
  sc.client_tcp_port,
  sc.endpoint_tcp_address,
  sc.endpoint_tcp_port,
  sc.bytes_up,
  sc.bytes_down,
  sc.closed_reason
from session s
  join session_state ss on
    s.public_id = ss.session_id
  left join session_connection sc on
    s.public_id = sc.session_id;

-- Add dropped warehouse views back, no changes
create view whx_host_dimension_source as
select -- id is the first column in the target view
       h.public_id                     as host_id,
       case when sh.public_id is not null then 'static host'
            when ph.public_id is not null then 'plugin host'
            else 'Unknown' end          as host_type,
       case when sh.public_id is not null then coalesce(sh.name, 'None')
            when ph.public_id is not null then coalesce(ph.name, 'None')
            else 'Unknown' end          as host_name,
       case when sh.public_id is not null then coalesce(sh.description, 'None')
            when ph.public_id is not null then coalesce(ph.description, 'None')
            else 'Unknown' end          as host_description,

       hs.public_id                     as host_set_id,
       case when shs.public_id is not null then 'static host set'
            when phs.public_id is not null then 'plugin host set'
            else 'Unknown' end          as host_set_type,
       case
         when shs.public_id is not null then coalesce(shs.name, 'None')
         when phs.public_id is not null then coalesce(phs.name, 'None')
         else 'None'
         end                            as host_set_name,
       case
         when shs.public_id is not null then coalesce(shs.description, 'None')
         when phs.public_id is not null then coalesce(phs.description, 'None')
         else 'None'
         end                            as host_set_description,
       hc.public_id                     as host_catalog_id,
       case when shc.public_id is not null then 'static host catalog'
            when phc.public_id is not null then 'plugin host catalog'
            else 'Unknown' end          as host_catalog_type,
       case
         when shc.public_id is not null then coalesce(shc.name, 'None')
         when phc.public_id is not null then coalesce(phc.name, 'None')
         else 'None'
         end                            as host_catalog_name,
       case
         when shc.public_id is not null then coalesce(shc.description, 'None')
         when phc.public_id is not null then coalesce(phc.description, 'None')
         else 'None'
         end                            as host_catalog_description,
       t.public_id                     as target_id,
       'tcp target'                    as target_type,
       coalesce(t.name, 'None')        as target_name,
       coalesce(t.description, 'None') as target_description,
       coalesce(t.default_port, 0)     as target_default_port_number,
       t.session_max_seconds           as target_session_max_seconds,
       t.session_connection_limit      as target_session_connection_limit,
       p.public_id                     as project_id,
       coalesce(p.name, 'None')        as project_name,
       coalesce(p.description, 'None') as project_description,
       o.public_id                     as organization_id,
       coalesce(o.name, 'None')        as organization_name,
       coalesce(o.description, 'None') as organization_description
from host as h
       join host_catalog as hc                on h.catalog_id = hc.public_id
       join host_set as hs                    on h.catalog_id = hs.catalog_id
       join target_host_set as ts             on hs.public_id = ts.host_set_id
       join target_tcp as t                   on ts.target_id = t.public_id
       join iam_scope as p                    on t.project_id = p.public_id and p.type = 'project'
       join iam_scope as o                    on p.parent_id = o.public_id and o.type = 'org'

       left join static_host as sh            on sh.public_id = h.public_id
       left join host_plugin_host as ph       on ph.public_id = h.public_id
       left join static_host_catalog as shc   on shc.public_id = hc.public_id
       left join host_plugin_catalog as phc   on phc.public_id = hc.public_id
       left join static_host_set as shs       on shs.public_id = hs.public_id
       left join host_plugin_set as phs       on phs.public_id = hs.public_id
;

create view whx_credential_dimension_source as
select -- id is the first column in the target view
       s.public_id                              as session_id,
       coalesce(scd.credential_purpose, 'None') as credential_purpose,
       cl.public_id                             as credential_library_id,
       case
         when vcl is null then 'None'
         else 'vault credential library'
         end                                    as credential_library_type,
       coalesce(vcl.name, 'None')               as credential_library_name,
       coalesce(vcl.description, 'None')        as credential_library_description,
       coalesce(vcl.vault_path, 'None')         as credential_library_vault_path,
       coalesce(vcl.http_method, 'None')        as credential_library_vault_http_method,
       coalesce(vcl.http_request_body, 'None')  as credential_library_vault_http_request_body,
       cs.public_id                             as credential_store_id,
       case
         when vcs is null then 'None'
         else 'vault credential store'
         end                                    as credential_store_type,
       coalesce(vcs.name, 'None')               as credential_store_name,
       coalesce(vcs.description, 'None')        as credential_store_description,
       coalesce(vcs.namespace, 'None')          as credential_store_vault_namespace,
       coalesce(vcs.vault_address, 'None')      as credential_store_vault_address,
       t.public_id                              as target_id,
       'tcp target'                             as target_type,
       coalesce(tt.name, 'None')                as target_name,
       coalesce(tt.description, 'None')         as target_description,
       coalesce(tt.default_port, 0)             as target_default_port_number,
       tt.session_max_seconds                   as target_session_max_seconds,
       tt.session_connection_limit              as target_session_connection_limit,
       p.public_id                              as project_id,
       coalesce(p.name, 'None')                 as project_name,
       coalesce(p.description, 'None')          as project_description,
       o.public_id                              as organization_id,
       coalesce(o.name, 'None')                 as organization_name,
       coalesce(o.description, 'None')          as organization_description
from session_credential_dynamic as scd,
     session as s,
     credential_library as cl,
     credential_store as cs,
     credential_vault_library as vcl,
     credential_vault_store as vcs,
     target as t,
     target_tcp as tt,
     iam_scope as p,
     iam_scope as o
where scd.library_id = cl.public_id
  and cl.store_id = cs.public_id
  and vcl.public_id = cl.public_id
  and vcs.public_id = cs.public_id
  and s.public_id = scd.session_id
  and s.target_id = t.public_id
  and t.public_id = tt.public_id
  and p.public_id = t.project_id
  and p.type = 'project'
  and o.public_id = p.parent_id
  and o.type = 'org';

-- Replaced in 87/01_session.up.sql
drop trigger immutable_columns on session;
create trigger immutable_columns before update on session
  for each row execute procedure immutable_columns('public_id', 'certificate', 'expiration_time', 'connection_limit',
    'create_time', 'endpoint', 'worker_filter', 'egress_worker_filter', 'ingress_worker_filter');

commit;
