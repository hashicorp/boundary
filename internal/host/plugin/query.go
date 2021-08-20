package plugin

const (
	upsertHostCatalogSecretQuery = `
insert into plugin_host_catalog_secret
  (catalog_id, secret, key_id)
values
  ($1, $2, $3)
on conflict (catalog_id) do update
  set secret  = excluded.secret,
      key_id  = excluded.key_id
returning *;
`

	deleteHostCatalogSecretQuery = `
delete from plugin_host_catalog_secret
 where catalog_id = $1;
`
)
