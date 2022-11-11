# Extending Boundary: adding additional field to an existing API

A very high level list of things to do
when you're adding an additional field to an existing API and corresponding CLI command.

## Add the new field to a repository

Once you've figured out that you need an additional field in Boundary's domain model,
then you need to build in support for your new field from the bottom up starting with a repository's database schema.

* Make schema changes:
  * Define the new column and provide for the migration of existing data
    * Create a new migration under `internal/db/schema/migrations/oss/postgres`

* Add the new field to the storage protobuf

  * storage protobufs are under: `internal/proto/controller/storage`
  * Define a gorm tag for the new field via `@gotags`
    (`@inject_tag` has been deprecated)
  * Define a `custom_options.v1.mask_mapping` for the field
    which maps the storage `this` field to the API `that` field
    (yes, it's the opposite of how it's defined for the API protobuf)
  * Run `make proto` after modifying storage protobuf

* Extend the existing repository function for Updating the resource to incorporate the new field.
  This could/may entail defining new options for the Update function.
* Check the repository's Create function for the resource,
  since you may need to incorporate the new field here as well.

## Add new fields to the API/SDK resource protobufs

Now that the repository supports the new field,
you can move on to adding this new field to Boundary's API layer and the generated SDK.
The first step in the process is to add it to the API/SDK protobufs.

* API protobufs are under: `internal/proto/controller/api/resources`
* Define a `custom_options.v1.mask_mapping` tag for the field
  which maps the API `this` field to the storage `that` field
  (yes, it's the opposite of how it's defined for a storage protobuf)
* Define a `custom_options.v1.generate_sdk_option` tag to change the SDK and add
  API options (DefaultX, WithX functions).
* Define a data classification/filter tag for the field via `@gotags`
  which specifies how sensitive/secret/public data
  will be handled for the API's audit events.
  See the [classification rubric](./classification-rubric.md)
  for guidelines on classification.
  Please write unit tests to verify the audit event is properly "redacted"
  (see the unit tests of `TestAuthMethod_Tags` for [examples][test example]).

* Run `make proto` and `make api` after modifying the API/SDK protobufs

## Update the API handler service

Now that the API protobufs have been updated,
you can move on to adding this new field to the API service handler.

* Service handlers are under: `internal/daemon/controller/handlers`
* Incorporate the new field into the handlers `updateInRepo` func.
  You'll need to incorporate the inbound protobuf's field with the repository's update function.
  This could include adding repository options to the Update function call
  or passing the new field as a parameter to the call.
  This work will be based on how you extended the repository in the previous steps.
* Incorporate the new field into the handler's `ToProto` function.

## Update the CLI's command for updating the resource

At this point, the new field is available via Boundary's API.
All that's left is to incorporate it into Boundary's CLI for the appropriate command.

* CLI commands are under: `internal/cmd/commands`
* Incorporate the new fields to the command's `funcs.go`.
  Just a suggestion here: you may want to define a const for the new field name
  and reuse it everywhere it's required (which is several places)
* Run `make cli` and `make install`, before attempting to test cli changes

[test example]: tests/api/authmethods/classification_test.go
