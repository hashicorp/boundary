# Vault Generic Credential Library DB Refactor
Historically, the "Vault generic" credential library was named just "Vault"
credential library. Over the course of Boundary's development, it was renamed to
"Vault generic" to better match its abilities and to conceptually separate it
from other Vault-specific credential libraries, however this nomenclature change
was not applied to database (or domain) entities. This migration applies this
nomenclature change at the database level, renaming all related entities to
match the new "Vault generic" name.

Currently, these database entities are either named or prefixed with
`credential_vault_library`. This migration changes them to be named or prefixed
with `credential_vault_generic_library`.

Additionally, `credential_vault_library` takes on a new meaning and is defined
as a new base table that holds information about all *Vault-specific* credential
libraries. `credential_vault_library` is a subtype table of
`credential_library`:

```
credential_library |> credential_vault_library |> credential_vault_generic_library
                   |                           |> credential_vault_ssh_cred_library
                   |                           |> any future Vault-specific credential libraries
                   |
In the future, we could also have:
                   |> base table for a non-Vault system's credlibs |> credential library subtype tables
```

While the history table for Vault generic credential libraries is renamed to
`credential_vault_generic_library_hst`, the overall history design remains
unchanged.

This pattern is being established due to the need to differentiate between the
systems that Boundary's credential libraries integrate with, for database
integrity purposes:

`credential_dynamic` is a base table that represents all renewable/revokable
dynamic credentials. `credential_vault_credential` is a subtype table that
represents renewable/revokable dynamic credentials (Vault leases). Given the
specificity of this design, these leases must be obtained by a Vault credential
library.

To enforce this, the `library_id` field in `credential_vault_credential` has a
foreign key constraint on `credential_vault_library(public_id)`, meaning only
Vault leases obtained by a Vault generic credential library can ever be inserted
into this table and therefore managed by Boundary.

With the future introduction of new Vault credential libraries that can also
issue Vault leases, this constraint becomes too restrictive and the design needs
to be extended. By redefining `credential_vault_library` as described above,
this refactor provides the backing for this to be done.
