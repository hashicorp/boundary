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
	extract(epoch from (least(now(), last_sync_time) + ?) - now())::int as resync_in
from host_plugin_set
order by need_sync desc, last_sync_time desc
limit 1;
`
)
