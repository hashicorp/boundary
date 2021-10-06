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
)
