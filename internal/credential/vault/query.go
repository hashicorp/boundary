package vault

const (
	insertTokenQuery = `
insert into credential_vault_token (
  token_sha256, -- $1
  token, -- $2
  store_id, -- $3
  key_id, -- $4
  status, -- $5
  last_renewal_time, -- $6
  expiration_time -- $7
) values (
  $1, -- token_sha256
  $2, -- token
  $3, -- store_id
  $4, -- key_id
  $5, -- status
  $6, -- last_renewal_time
  wt_add_seconds_to_now($7)  -- expiration_time
);
`
	insertLeaseQuery = `
insert into credential_vault_lease (
  public_id, -- $1
  library_id, -- $2
  session_id, -- $3
  token_sha256, -- $4
  lease_id, -- $5
  is_renewable, -- $6
  last_renewal_time, -- $7
  expiration_time -- $8
) values (
  $1, -- public_id
  $2, -- library_id
  $3, -- session_id
  $4, -- token_sha256
  $5, -- lease_id
  $6, -- is_renewable
  $7, -- last_renewal_time
  wt_add_seconds_to_now($8)  -- expiration_time
);
`
)
