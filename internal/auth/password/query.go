// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

const (
	authenticateQuery = `
select acct.name,                        -- Account.Name
       acct.description,                 -- Account.Description
       acct.login_name,                   -- Account.LoginName
       acct.public_id,                   -- Account.PublicId
       acct.auth_method_id,              -- Account.AuthMethodId
       acct.scope_id,                    -- Account.ScopeId
       acct.create_time,                 -- Account.CreateTime
       acct.update_time,                 -- Account.UpdateTime
       acct.version,                     -- Account.Version
       cred.private_id as credential_id, -- Account.CredentialId
       cred.private_id,                  -- Argon2Credential.PrivateId
       cred.password_conf_id,            -- Argon2Credential.PasswordConfId
       cred.salt,                        -- Argon2Credential.CtSalt/Salt
       cred.derived_key,                 -- Argon2Credential.DerivedKey
       conf.key_length,                  -- Argon2Configuration.KeyLength
       conf.iterations,                  -- Argon2Configuration.Iterations
       conf.memory,                      -- Argon2Configuration.Memory
       conf.threads,                     -- Argon2Configuration.Threads
       meth.password_conf_id = cred.password_conf_id as is_current_conf
  from auth_password_argon2_cred cred,
       auth_password_argon2_conf conf,
       auth_password_account acct,
       auth_password_method meth
 where acct.auth_method_id = @auth_method_id
   and acct.login_name = @login_name
   and cred.password_conf_id = conf.private_id
   and cred.password_account_id = acct.public_id
   and acct.auth_method_id = meth.public_id ;
`
	currentConfigForAccountQuery = `
select *
  from auth_password_current_conf
 where password_method_id
    in (
       select auth_method_id
         from auth_password_account
        where public_id = @public_id
    );
`
	estimateCountAccounts = `
select sum(reltuples::bigint) as estimate from pg_class where oid in ('auth_password_account'::regclass)
`
)
