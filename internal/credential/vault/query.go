package vault

const (
	insertToken = `
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
)
