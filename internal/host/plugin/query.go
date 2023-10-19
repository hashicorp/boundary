// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package plugin

const (
	upsertHostCatalogSecretQuery = `
insert into host_plugin_catalog_secret
  (catalog_id, secret, key_id)
values
  (@catalog_id, @secret, @key_id)
on conflict (catalog_id) do update
  set secret  = excluded.secret,
      key_id  = excluded.key_id
returning *;
`

	deleteHostCatalogSecretQuery = `
delete from host_plugin_catalog_secret
 where catalog_id = @catalog_id;
`

	setSyncNextRunInQuery = `
select
  need_sync as sync_now,
  sync_interval_seconds,
  case
    when sync_interval_seconds is null
      then
        extract(epoch from (least(now(), last_sync_time) + ?) - now())::int
    when sync_interval_seconds > 0
      then
        extract(epoch from (least(now(), last_sync_time)) - now())::int + sync_interval_seconds
    else
      0
  end resync_in
from host_plugin_set
order by need_sync desc, last_sync_time desc
limit 1;
`

	setSyncJobQuery = `
need_sync
  or
sync_interval_seconds is null and last_sync_time <= wt_add_seconds_to_now(?)
  or
sync_interval_seconds > 0 and wt_add_seconds(sync_interval_seconds, last_sync_time) <= current_timestamp
`

	updateSyncDataQuery = `
update host_plugin_set
set
  last_sync_time = current_timestamp,
  need_sync = false
where public_id = ?
`

	estimateCountHosts = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('host_plugin_host'::regclass)
`
)
