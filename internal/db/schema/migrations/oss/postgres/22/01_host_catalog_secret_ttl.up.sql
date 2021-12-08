begin;
  alter table host_plugin_catalog_secret
    add column ttl_seconds int
      constraint ttl_seconds_not_less_than_zero
        check(ttl_seconds >= 0);

-- replace host_plugin_catalog_with_secret to add the ttl_seconds secret column.
drop view host_plugin_catalog_with_secret;
create view host_plugin_catalog_with_secret as
select
  hc.public_id,
  hc.scope_id,
  hc.plugin_id,
  hc.name,
  hc.description,
  hc.create_time,
  hc.update_time,
  hc.version,
  hc.secrets_hmac,
  hc.attributes,
  hcs.secret,
  hcs.key_id,
  hcs.create_time as persisted_create_time,
  hcs.update_time as persisted_update_time,
  hcs.ttl_seconds as persisted_ttl_seconds
from
  host_plugin_catalog hc
    left outer join host_plugin_catalog_secret hcs   on hc.public_id = hcs.catalog_id;
comment on view host_plugin_catalog_with_secret is
  'host plugin catalog with its associated persisted data';

commit;
