## Boundary Database Design Principles

Boundary team members have decades of experience in database design. This knowledge has formed the following principles.

### Domain Types 

[Domain Types](./0/01_domain_types.up.sql) are used for commonly used types and triggers. Each
domain type is prefixed with `wt_` which is a callback to Boundary's "project" name (Watchtower). 
Some domain types may have associated triggers which will help ensure data integrity. 

When using `wt_timestamp` the triggers `default_create_time()` and `update_time_column()` are useful. With the use of these triggers, and setting the `wt_timestamp` type column to be immutable, it will protect against application code setting a table to be "in the future" as well as prevent against bad actors. 

It is strongly advised to look over the multiple domain types file before starting a first draft at a schema.


### Keys

Most tables use the `wt_public_id` type to create a `public_id` column and use that as the primary key.


### Constraints

All foreign key constraints should be named after their reference, and end in `_fkey`:

```
owner string not null
    constraint wt_member_fkey
        references wt_member(name)
```

Contraints for checking uniqueness reference the column names and end in `_uq`:

```
    constraint public_id_owner_uq
        unique(public_id, owner)
```

It is important to [note](https://github.com/hashicorp/boundary/blob/248e1f36b5ed3ed24a0ec92e47a2de70fdb5b4ef/internal/db/schema/migrations/postgres/10/03_credential.up.sql#L13-L14) that the order of the columns is important for performance. (Someone who actually understands this should explain why)

Constraints for checks tend to explain the check itself:

```
constraint tls_server_name_must_not_be_empty

constraint salt_must_be_at_least_16_bytes
```

### Parent and Sub Tables

When implementing a feature where the behavior will differ based off attributes provided by 
a user, parent and sub tables are used.

A great example of this is the [credential store](https://github.com/hashicorp/boundary/blob/248e1f36b5ed3ed24a0ec92e47a2de70fdb5b4ef/internal/db/schema/migrations/postgres/10/03_credential.up.sql#L4). The credentials store is a parent to the [credential vault store](https://github.com/hashicorp/boundary/blob/248e1f36b5ed3ed24a0ec92e47a2de70fdb5b4ef/internal/db/schema/migrations/postgres/10/04_vault_credential.up.sql) table. 
By breaking these out into parent/sub tables this allows developers to be very specific in the way the entities relate to one another. 

Naming of parent/sub tables should follow the above example of `credential_store` and `credential_vault_store`. Another example would be, `event_sink` with `event_stderr_sink` and `event_file_sink`. The naming for a subtable is the parent table name with an identifier added in the middle.

An [insert and delete trigger](https://github.com/hashicorp/boundary/blob/main/internal/db/schema/migrations/postgres/9/02_oidc_managed_group.up.sql#L62-L74) for the subtables are needed to ensure that upon deletion of a parent table that the subtables are not abandoned.

 
 
### Enumeration Tables 

Enumeration Tables are used within Boundary to restrict the different values that can be inserted into a column. There are many types of enumeration tables, such as [this one](https://github.com/hashicorp/boundary/blob/main/internal/db/schema/migrations/postgres/10/04_vault_credential.up.sql#L122). When creating an enumeration table the table name must end in `_enm`. A check is used to allow only certain variables (strings, ints, etc) is inserted into the column. 

The [immutable column trigger](https://github.com/hashicorp/boundary/blob/main/internal/db/schema/migrations/postgres/0/01_domain_types.up.sql#L126) is then added to ensure that the column in the enumeration table is not able to be changed. 

Lastly, when referencing the enumeration table as a foreign key, it should always be set to:

```
on delete restrict
on update cascade
```


### Example
A rough example of these principles is available [here](./examples/design_principles_examples.sql)