# kms package 

[![Go Reference](https://pkg.go.dev/badge/github.com/hashicorp/go-kms-wrapping/extras/kms/kms.svg)](https://pkg.go.dev/github.com/hashicorp/go-kms-wrapping/extras/kms)

kms is a package that provides key management system features for
go-kms-wrapping `Wrappers`. 

The following domain terms are key to understanding the system and how to use
it:

- `wrapper`: all keys within the system are a `Wrapper` from go-kms-wrapping.

- `root external wrapper`: the external wrapper that will serve as the root of
  trust for the kms system.  Typically you'd get this root wrapper via
  go-kms-wrapper from a KMS provider.  See the go-kms-wrapper docs for further
  details. 
  
- `scope`: a scope defines a rotational boundary for a set of keys.  The system
  tracks only the scope identifier and which is used to find keys with a
  specific scope.  
  
  **IMPORTANT**: You should define a FK from `kms_root_key.scope_id` with
  cascading deletes and updates to the PK of the table within your domain that
  contains scopes.  This FK will prevent orphaned kms keys.
  
  For example, you could assign organizations and projects
  scope IDs and then associate a set of keys with each org and project within
  your domain. 

- `root key`:  the KEKs (key-encryption-key) of the system.  

- `data key`:  the DEKs (data-encryption-key) of the system and must have a
  parent root key and a purpose.  

- `data key version`: versions of DEKs (data-encryption-key) which are used to
  encrypt/decrypt data.  

  **IMPORTANT**: You should define a FK with a restricted delete from any
  application table that stores encrypted data to 
  `kms_data_key_version(private_id)`.  This FK will prevent kms keys from being
  deleted that are currently being used to encrypt/decrypt data.
  
  For example, you have a table named `oidc` which contains the app's encrypted
  oidc client_secret. The `oidc` table should have a `key_version_id` column with a
  restricted FK to `kms_data_key_version(private_id)` which prevents in use DEKs
  from being deleted. 

- `purpose`:  Each data key (DEK) must have a one purpose.  For
  example, you could define a purpose of `client-secrets` for a DEK that will be
  used encrypt/decrypt wrapper operations on `client-secrets`
  

<hr>

### Database Schema

You'll find the database schema within the migrations directory.
Currently postgres and sqlite are supported.  The implementation does make some
use of triggers to ensure some of its data integrity. 

The migrations are intended to be incorporated into your existing go-migrate
migrations.  Feel free to change the migration file names, as long as they are
applied in the same order as defined here.  FYI, the migrations include
`kms_version` table which is used to ensure that the schema and module are
compatible. 

```
High-level ERD                                          
                                                          
                                                          
             ┌───────────────────────────────┐            
             │                               ○            
             ┼                               ┼            
┌────────────────────────┐      ┌────────────────────────┐
│      kms_root_key      │      │      kms_data_key      │
├────────────────────────┤      ├────────────────────────┤
│private_id              │      │private_id              │
│scope_id                │      │root_key_id             │
│                        │      │purpose                 │
└────────────────────────┘      │                        │
             ┼                  └────────────────────────┘
             │                               ┼            
             │                               │            
             │                               │            
             │                               │            
             ┼                               ┼            
            ╱│╲                             ╱│╲           
┌────────────────────────┐      ┌────────────────────────┐
│  kms_root_key_version  │      │  kms_data_key_version  │
├────────────────────────┤      ├────────────────────────┤
│private_id              │      │private_id              │
│root_key_id             │      │data_key_id             │
│key                     │      │root_key_id             │
│version                 │      │key                     │
│                        │      │version                 │
└────────────────────────┘      └────────────────────────┘
             ┼                               ┼            
             │                               ○            
             └───────────────────────────────┘               
          
```
