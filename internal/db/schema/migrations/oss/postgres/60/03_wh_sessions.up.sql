-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- replaced view in 44/03_targets.up.sql
  drop view whx_host_dimension_source;
  create view whx_host_dimension_source as
  with
  host_sources (
    host_id, host_type, host_name, host_description,
    host_set_id, host_set_type, host_set_name, host_set_description,
    host_catalog_id, host_catalog_type, host_catalog_name, host_catalog_description,
    target_id, target_type, target_name, target_description,
    target_default_port_number, target_session_max_seconds, target_session_connection_limit,
    project_id, project_name, project_description,
    organization_id, organization_name, organization_description
  ) as (
    select 
      h.public_id                       as host_id,
      case when sh.public_id is not null then 'static host'
            when ph.public_id is not null then 'plugin host'
            else 'Unknown' end          as host_type,
      case when sh.public_id is not null then coalesce(sh.name, 'None')
            when ph.public_id is not null then coalesce(ph.name, 'None')
            else 'Unknown' end          as host_name,
      case when sh.public_id is not null then coalesce(sh.description, 'None')
            when ph.public_id is not null then coalesce(ph.description, 'None')
            else 'Unknown' end          as host_description,
      hs.public_id                      as host_set_id,
      case when shs.public_id is not null then 'static host set'
            when phs.public_id is not null then 'plugin host set'
            else 'Unknown' end          as host_set_type,
      case
        when shs.public_id is not null then coalesce(shs.name, 'None')
        when phs.public_id is not null then coalesce(phs.name, 'None')
        else 'None'
        end                             as host_set_name,
      case
        when shs.public_id is not null then coalesce(shs.description, 'None')
        when phs.public_id is not null then coalesce(phs.description, 'None')
        else 'None'
        end                             as host_set_description,
      hc.public_id                      as host_catalog_id,
      case when shc.public_id is not null then 'static host catalog'
            when phc.public_id is not null then 'plugin host catalog'
            else 'Unknown' end          as host_catalog_type,
      case
        when shc.public_id is not null then coalesce(shc.name, 'None')
        when phc.public_id is not null then coalesce(phc.name, 'None')
        else 'None'
        end                             as host_catalog_name,
      case
        when shc.public_id is not null then coalesce(shc.description, 'None')
        when phc.public_id is not null then coalesce(phc.description, 'None')
        else 'None'
        end                             as host_catalog_description,
      t.public_id                       as target_id,
      'tcp target'                      as target_type,
      coalesce(t.name, 'None')          as target_name,
      coalesce(t.description, 'None')   as target_description,
      coalesce(t.default_port, 0)       as target_default_port_number,
      t.session_max_seconds             as target_session_max_seconds,
      t.session_connection_limit        as target_session_connection_limit,
      p.public_id                       as project_id,
      coalesce(p.name, 'None')          as project_name,
      coalesce(p.description, 'None')   as project_description,
      o.public_id                       as organization_id,
      coalesce(o.name, 'None')          as organization_name,
      coalesce(o.description, 'None')   as organization_description
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
  ),
  host_target_address (
    host_id, host_type, host_name, host_description,
    host_set_id, host_set_type, host_set_name, host_set_description,
    host_catalog_id, host_catalog_type, host_catalog_name, host_catalog_description,
    target_id, target_type, target_name, target_description,
    target_default_port_number, target_session_max_seconds, target_session_connection_limit,
    project_id, project_name, project_description,
    organization_id, organization_name, organization_description
  ) as (
    select
      'Not Applicable'                as host_id,
      'direct address'                as host_type,
      'Not Applicable'                as host_name,
      'Not Applicable'                as host_description,
      'Not Applicable'                as host_set_id,
      'Not Applicable'                as host_set_type,
      'Not Applicable'                as host_set_name,
      'Not Applicable'                as host_set_description,
      'Not Applicable'                as host_catalog_id,
      'Not Applicable'                as host_catalog_type,
      'Not Applicable'                as host_catalog_name,
      'Not Applicable'                as host_catalog_description,
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
    from target_tcp as t
    right join target_address as ta on t.public_id = ta.target_id
    left join iam_scope as p        on p.public_id = t.project_id
    left join iam_scope as o        on o.public_id = p.parent_id
  )
  select * from host_sources
  union
  select * from host_target_address;

  -- replaced function in 26/03_wh_network_address_dimensions.up.sql
  create or replace function wh_upsert_host() returns trigger
  as $$
  declare
    p_target_id    wt_public_id;
    p_host_key     wh_dim_key;
    src            whx_host_dimension_target%rowtype;
    target         whx_host_dimension_target%rowtype;
    addr_group_key wh_dim_key;
  begin
    select target_id into p_target_id
      from session
    where session.public_id = new.session_id;

    if p_target_id is null then
      raise exception 'target_id is null';
    end if;

    select * into target
    from whx_host_dimension_target as t
    where t.host_id               = new.host_id
      and t.host_set_id           = new.host_set_id
      and t.target_id             = p_target_id;

    select wh_upsert_network_address_dimension(new.host_id) into addr_group_key;

    select target.key, addr_group_key, t.* into src
    from whx_host_dimension_source as t
    where t.host_id               = new.host_id
      and t.host_set_id           = new.host_set_id
      and t.target_id             = p_target_id;

    if src is distinct from target then

      -- expire the current row
      update wh_host_dimension
      set current_row_indicator = 'Expired',
          row_expiration_time   = current_timestamp
      where host_id               = new.host_id
        and host_set_id           = new.host_set_id
        and target_id             = p_target_id
        and current_row_indicator = 'Current';

      -- insert a new row
      insert into wh_host_dimension (
        host_id,                    host_type,                  host_name,                       host_description,
        network_address_group_key,
        host_set_id,                host_set_type,              host_set_name,                   host_set_description,
        host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
        target_id,                  target_type,                target_name,                     target_description,
        target_default_port_number, target_session_max_seconds, target_session_connection_limit,
        project_id,                 project_name,               project_description,
        organization_id,            organization_name,          organization_description,
        current_row_indicator,      row_effective_time,         row_expiration_time
      )
      select host_id,                    host_type,                  host_name,                       host_description,
             addr_group_key,
             host_set_id,                host_set_type,              host_set_name,                   host_set_description,
             host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
             target_id,                  target_type,                target_name,                     target_description,
             target_default_port_number, target_session_max_seconds, target_session_connection_limit,
             project_id,                 project_name,               project_description,
             organization_id,            organization_name,          organization_description,
             'Current',                  current_timestamp,          'infinity'::timestamptz
      from whx_host_dimension_source
      where host_id               = new.host_id
        and host_set_id           = new.host_set_id
        and target_id             = p_target_id;

    end if;

    select key into p_host_key
    from wh_host_dimension as t
    where t.current_row_indicator = 'Current'
      and t.host_id               = new.host_id
      and t.host_set_id           = new.host_set_id
      and t.target_id             = p_target_id;

    update wh_session_accumulating_fact
      set host_key = p_host_key
    where session_id = new.session_id;

    return new;
  end;
  $$ language plpgsql;

  create trigger wh_update_session_connection_accumulating_fact after insert on session_host_set_host
    for each row execute procedure wh_upsert_host();

  -- Replaces function from 16/04_wh_credential_dimension.up.sql
  -- Replaced in 82/02_wh_upsert_user_refact.up.sql
  create or replace function wh_insert_session() returns trigger
  as $$
  declare
    new_row wh_session_accumulating_fact%rowtype;
  begin
    with
    pending_timestamp (date_dim_key, time_dim_key, ts) as (
      select wh_date_key(start_time), wh_time_key(start_time), start_time
        from session_state
       where session_id = new.public_id
         and state      = 'pending'
    )
    insert into wh_session_accumulating_fact (
           session_id,
           auth_token_id,
           host_key,
           user_key,
           credential_group_key,
           session_pending_date_key,
           session_pending_time_key,
           session_pending_time
    )
    select new.public_id,
           new.auth_token_id,
           'no host source', -- will be updated by wh_upsert_host
           wh_upsert_user(new.user_id, new.auth_token_id),
           'no credentials', -- will be updated by wh_upsert_credential_group
           pending_timestamp.date_dim_key,
           pending_timestamp.time_dim_key,
           pending_timestamp.ts
      from pending_timestamp
      returning * into strict new_row;
    return null;
  end;
  $$ language plpgsql;

  insert into wh_host_dimension (
    key,
    host_id, host_type, host_name, host_description,
    host_set_id, host_set_type, host_set_name, host_set_description,
    host_catalog_id, host_catalog_type, host_catalog_name, host_catalog_description, 
    target_id, target_type, target_name, target_description, target_default_port_number, target_session_max_seconds, target_session_connection_limit,
    project_id, project_name, project_description, organization_id, organization_name, organization_description,
    current_row_indicator, row_effective_time, row_expiration_time, network_address_group_key
  )
  values
  (
    'no host source',
    'None',                'None',                  'None',                      'None',
    'None',                'None',                  'None',                      'None',
    'None',                'None',                  'None',                      'None',
    'None',                'None',                  'None',                      'None',                   -1,                  -1,               -1,
    '00000000000',         'None',                  'None',                      '00000000000',        'None',              'None',
    'Current',              now(),                  'infinity'::timestamptz,     'Unknown'
  );

  create function wh_upsert_direct_network_address_dimension(p_address text, p_target_id text) returns wh_dim_key
  as $$
  declare
    p_address_type text := 'Not Applicable';
    p_ip_address_family text := 'Not Applicable';
    p_private_ip_address_indicator text := 'Not Applicable';
    p_dns_name text := 'Not Applicable';
    p_ip4_address text := 'Not Applicable';
    p_ip6_address text := 'Not Applicable';
    nag_key wh_dim_key;
  begin
    if wh_try_cast_inet(p_address) is null then
      p_address_type := 'DNS Name';
      p_dns_name := p_address;
    else 
      p_address_type := 'IP Address';
      p_private_ip_address_indicator := wh_private_address_indicator(wh_try_cast_inet(p_address));
    end if;

    if family(wh_try_cast_inet(p_address)) = 4 then
      p_ip_address_family := 'IPv4';
      p_ip4_address := host(wh_try_cast_inet(p_address));
    elsif family(wh_try_cast_inet(p_address)) = 6 then
      p_ip_address_family := 'IPv6';
      p_ip6_address := host(wh_try_cast_inet(p_address));
    end if;

    insert into wh_network_address_dimension 
      (address, address_type, ip_address_family, private_ip_address_indicator, dns_name, ip4_address, ip6_address)
    values
      (p_address, p_address_type, p_ip_address_family, p_private_ip_address_indicator, p_dns_name, p_ip4_address, p_ip6_address) on conflict do nothing;

    select distinct g.network_address_group_key into nag_key
    from wh_network_address_group_membership g
    left join wh_host_dimension h on g.network_address_group_key = h.network_address_group_key
    where g.network_address = p_address
      and h.current_row_indicator = 'Current'
      and h.target_id = p_target_id
      and h.host_id = 'Not Applicable'
      and h.host_set_id = 'Not Applicable';

    if nag_key is null then
      select network_address_group_key into nag_key
      from wh_host_dimension h
      where h.current_row_indicator = 'Current'
        and h.host_id               = 'Not Applicable'
        and h.host_set_id           = 'Not Applicable'
        and h.target_id             = p_target_id;
    end if;

    if nag_key is null then
      insert into wh_network_address_group default values returning key into nag_key;
    end if;

    insert into wh_network_address_group_membership
      (network_address_group_key, network_address)
    values
      (nag_key, p_address) on conflict do nothing;

    return nag_key;
  end
  $$ language plpgsql;

  create function wh_upsert_host_direct_network_address() returns trigger
  as $$
  declare
    p_address      text;
    src            whx_host_dimension_target%rowtype;
    target         whx_host_dimension_target%rowtype;
    addr_group_key wh_dim_key;
    p_host_key     wh_dim_key;
  begin
    select address into p_address
      from target_address
    where target_address.target_id = new.target_id;

    if p_address is null then
      raise exception 'target address is null';
    end if;

    select * into target
    from whx_host_dimension_target as t
    where t.host_id               = 'Not Applicable'
      and t.host_set_id           = 'Not Applicable'
      and t.target_id             = new.target_id;

    select wh_upsert_direct_network_address_dimension(p_address, new.target_id) into addr_group_key;

    select target.key, addr_group_key, t.* into src
    from whx_host_dimension_source as t
    where t.host_id               = 'Not Applicable'
      and t.host_set_id           = 'Not Applicable'
      and t.target_id             = new.target_id;

    if src is distinct from target then

      -- expire the current row
      update wh_host_dimension
      set current_row_indicator = 'Expired',
          row_expiration_time   = current_timestamp
      where host_id               = 'Not Applicable'
        and host_set_id           = 'Not Applicable'
        and target_id             = new.target_id
        and current_row_indicator = 'Current';

      -- insert a new row
      insert into wh_host_dimension (
        host_id,                    host_type,                  host_name,                       host_description,
        network_address_group_key,
        host_set_id,                host_set_type,              host_set_name,                   host_set_description,
        host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
        target_id,                  target_type,                target_name,                     target_description,
        target_default_port_number, target_session_max_seconds, target_session_connection_limit,
        project_id,                 project_name,               project_description,
        organization_id,            organization_name,          organization_description,
        current_row_indicator,      row_effective_time,         row_expiration_time
      )
      select host_id,                    host_type,                  host_name,                       host_description,
             addr_group_key,
             host_set_id,                host_set_type,              host_set_name,                   host_set_description,
             host_catalog_id,            host_catalog_type,          host_catalog_name,               host_catalog_description,
             target_id,                  target_type,                target_name,                     target_description,
             target_default_port_number, target_session_max_seconds, target_session_connection_limit,
             project_id,                 project_name,               project_description,
             organization_id,            organization_name,          organization_description,
             'Current',                  current_timestamp,          'infinity'::timestamptz
      from whx_host_dimension_source
      where host_id               = 'Not Applicable'
        and host_set_id           = 'Not Applicable'
        and target_id             = new.target_id;

    end if;

    select key into p_host_key
    from wh_host_dimension as t
    where t.current_row_indicator = 'Current'
      and t.host_id               = 'Not Applicable'
      and t.host_set_id           = 'Not Applicable'
      and t.target_id             = new.target_id;

    update wh_session_accumulating_fact
      set host_key = p_host_key
    where session_id = new.session_id;

    return new;
  end;
  $$ language plpgsql;

  create trigger wh_update_session_connection_accumulating_fact after insert on session_target_address
    for each row execute procedure wh_upsert_host_direct_network_address();

commit;
