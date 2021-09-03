package plugin

const (
	upsertHostCatalogSecretQuery = `
insert into host_plugin_catalog_secret
  (catalog_id, secret, key_id)
values
  ($1, $2, $3)
on conflict (catalog_id) do update
  set secret  = excluded.secret,
      key_id  = excluded.key_id
returning *;
`

	deleteHostCatalogSecretQuery = `
delete from host_plugin_catalog_secret
 where catalog_id = $1;
`
)
