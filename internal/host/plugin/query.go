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

	// FIXME: This needs to take into account sync_interval_seconds being positive
	setSyncNextRunInQuery = `
select
  need_sync as sync_now,
	extract(epoch from (least(now(), last_sync_time) + ?) - now())::int as resync_in
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
)
