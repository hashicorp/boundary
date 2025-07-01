# kms package CHANGELOG

Canonical reference for changes, improvements, and bugfixes for the kms package.

## Bug fixes
* Explicitly naming FK and unique constraints so they can be referenced by name
  in the future if any changes are required. Add the `kms` prefix to the
  `update_time_column()` function. 
  ([PR](https://github.com/hashicorp/go-kms-wrapping/pull/88)).

  The decision was made to make these changes by modifying existing migrations,
  so if you've already installed this package, you'll need to review the PR and
  make the changes by hand in a new migration.

## Breaking changes
* Publicly expose key versions.
  The `Key` type now contains a `Versions` slice which holds the versions of the key.
  A version of a key is what holds the key material. When a key is rotated, a new
  version is created, and the old version (now deactivated) is only used for
  decrypting existing data encrypted with it. The new version is used to encrypt
  new data. A deactivated version can be revoked (destroyed), but care should be
  taken to ensure that no existing data is encrypted with the version before doing so.
  Using the foreign key relationships recommended in the [README](./README.md) will
  prevent this from happening.
  The `KeyVersion` type holds metadata about the key version.

## Enhancements
* `WithKeyId` has been deprecated in favor of the new `WithKeyVersionId`.
* `RevokeKey` has been deprecated in favor of the new `RevokeKeyVersion`.
* Added `ListDataKeyReferencers` to allow listing the names of tables referencing the
  data key version table's private_id column. This can be useful when finding what
  data needs to be re-encrypted before destroying a key version.

