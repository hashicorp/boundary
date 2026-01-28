-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

alter table host_plugin_catalog
  add column secrets_hmac bytea
    constraint secrets_hmac_null_or_not_empty
    check(secrets_hmac is null or length(secrets_hmac) > 0);

-- Updated view in 44/02_hosts.up.sql
-- host_plugin_catalog_with_secret is useful for reading a plugin catalog with
-- its associated persisted data.
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
  hcs.update_time as persisted_update_time
from
  host_plugin_catalog hc
    left outer join host_plugin_catalog_secret hcs   on hc.public_id = hcs.catalog_id;
comment on view host_plugin_catalog_with_secret is
  'host plugin catalog with its associated persisted data';

commit;