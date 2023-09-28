// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package static

const (
	credStaticUsernamePasswordRewrapQuery = `
select distinct
  userpass.public_id,
  userpass.password_encrypted,
  userpass.key_id
from credential_static_username_password_credential userpass
  inner join credential_static_store store
    on store.public_id = userpass.store_id
where store.project_id = ?
  and userpass.key_id = ?;
`

	credStaticSshPrivKeyRewrapQuery = `
select distinct
  ssh.public_id,
  ssh.private_key_encrypted,
  ssh.private_key_passphrase_encrypted,
  ssh.key_id
from credential_static_ssh_private_key_credential ssh
  inner join credential_static_store store
    on store.public_id = ssh.store_id
where store.project_id = ?
  and ssh.key_id = ?;
`

	credStaticJsonRewrapQuery = `
select distinct
  json.public_id,
  json.object_encrypted,
  json.key_id
from credential_static_json_credential json
  inner join credential_static_store store
    on store.public_id = json.store_id
where store.project_id = ?
  and json.key_id = ?;
`

	estimateCountCredentialStores = `
select reltuples::bigint as estimate from pg_class where oid in ('credential_static_store'::regclass)
`

	estimateCountCredentials = `
select sum(reltuples::bigint) as estimate
  from pg_class
 where oid in (
  'credential_static_json_credential'::regclass,
  'credential_static_username_password_credential'::regclass,
  'credential_static_ssh_private_key_credential'::regclass
 )`
)
