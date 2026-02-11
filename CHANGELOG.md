# Boundary CHANGELOG

Canonical reference for changes, improvements, and bugfixes for Boundary.

## 0.21.X (2026/XX/XX)

### New and Improved

* cli: Added optional flags `-sort-by` and `-sort-direction` to `boundary search`. These flags can be used to control sorting when searching the client cache and the resource is `sessions` or `targets`. ([PR](https://github.com/hashicorp/boundary/pull/6383))
* The client cache search API now supports the `sort_by` and `sort_direction` query parameters when searching `sessions` or `targets`. ([PR](https://github.com/hashicorp/boundary/pull/6383))

## 0.21.1 (2026/02/10)

### Security

* Go version bumped to 1.25.7 to address CVE-2025-61730 ([PR](https://github.com/hashicorp/boundary/pull/6409))
* Go Cryptography dependency update to address CVE-2025-58181 and CVE-2025-47914
  ([PR](https://github.com/hashicorp/boundary/pull/6272))

## 0.21.0 (2025/12/11)

### New and Improved

* Vault LDAP has been added as a credential provider ([PR](https://github.com/hashicorp/boundary/pull/6222))
* Added support for host key verification when connecting to an SSH target by
  providing a `known_hosts` file. ([PR](https://github.com/hashicorp/boundary/pull/6263))
* Added new credential type for password. ([PR](https://github.com/hashicorp/boundary/pull/6207))
* ui: Optimized loading of table filters and improved table search support ([PR](https://github.com/hashicorp/boundary-ui/pull/3053))
* cli: `boundary connect` will close unused sessions when there is no longer a
  connection being actively proxied. This behavior can be modified via the
  `-inactive-timeout=<duration>` command-line argument ([PR](https://github.com/hashicorp/boundary/pull/6232))
* cli: `boundary connect redis` can now consume password credentials ([PR](https://github.com/hashicorp/boundary/pull/6213))
* AWS KMS credential handling now allows the use of shared credential files.
  Additionally, the `default` profile is now included in the credential chain
  by default if it exists. ([PR](https://github.com/hashicorp/boundary/pull/6286))

### Bug fixes

* ui: Show username for OIDC auth method in user menu ([PR](https://github.com/hashicorp/boundary-ui/pull/2930))
* `boundary connect rdp` no longer opens a new window for each call on mac. ([PR](https://github.com/hashicorp/boundary/pull/6232))
* Removed the error log during RDP basic settings exchange: When you connect to
  an RDP target using the built-in Windows Remote Desktop Connection app. ([PR](https://github.com/hashicorp/boundary/pull/6136))

## 0.20.2 (2026/02/10)

### Security

* Go version bumped to 1.25.7 to address CVE-2025-61730 ([PR](https://github.com/hashicorp/boundary/pull/6409))
* Go Cryptography dependency update to address CVE-2025-58181 and CVE-2025-47914
  ([PR](https://github.com/hashicorp/boundary/pull/6272))

## 0.20.1 (2025/11/03)

### New and Improved

* Added a complete IBM Key Protect wrapper implementation with configuration options and KMS client integration ([PR](https://github.com/hashicorp/go-kms-wrapping/pull/292))

## 0.20.0 (2025/09/25)

### New and Improved

* Update cap/ldap pkg to latest version to address possible concurreny issue ([PR](https://github.com/hashicorp/boundary/pull/6107))
* Added support for RDP targets and RDP credential injection for connecting to
  Windows machines. RDP credential injection supports both NTLM and Kerberos
  authentication.
* Added new credential type for username, password, and domain credentials.
* cli: Added `boundary connect mysql` command for connecting to MySQL targets.
  This new helper command allows users to authorize sessions against MySQL
  targets and automatically invoke a MySQL client with the appropriate
  connection parameters and credentials.
* cli: Added `boundary connect mongo` command for connecting to MongoDB targets.
  This new helper command allows users to authorize sessions against MongoDB
  targets and automatically invoke a MongoDB client with the appropriate
  connection parameters and credentials.
* Adds support to parse User-Agent headers and emit them in telemetry events
  ([PR](https://github.com/hashicorp/boundary/pull/5645)).
* cli: Added `boundary connect cassandra` command for connecting to Cassandra targets.
  This new helper command allows users to authorize sessions against Cassandra
  targets and automatically invoke a Cassandra client with the appropriate
  connection parameters and credentials. Currently only username/password credentials are automatically attached.
* cli: Added `boundary connect redis` command for connecting to Redis targets.
  This new helper command allows users to authorize sessions against Redis
  targets and automatically invoke a Redis client with the appropriate
  connection parameters and credentials. Currently only username/password credentials are automatically attached.
* ui: Improved load times for resource tables with search and filtering capabilities by replacing indexeddb for local data storage with sqlite (WASM) and OPFS ([PR](https://github.com/hashicorp/boundary-ui/pull/2984))

### Bug fixes
* ui: Fixed rendering bug where header for the Host details page rendered multiple times ([PR](https://github.com/hashicorp/boundary-ui/pull/2980))
* ui: Fixed bug where worker tags could not be removed when creating a new worker ([PR](https://github.com/hashicorp/boundary-ui/pull/2928))

### Deprecations/Changes

* Modified parsing logic for various IP/host/address fields across Boundary.
  Notably, for some fields, Boundary previously required bracket-enclosed
  IPv6 addresses (eg: `[::1]`). With this change, if the provided address is
  just an IPv6 literal, enclosing the address in brackets is not valid.
  Additionally, an input address containing an IPv6 literal may be modified by
  Boundary to conform with RFC 5952.
  ([PR](https://github.com/hashicorp/boundary/pull/5599))

## 0.19.4 (2026/02/10)

### Security

* Go version bumped to 1.25.7 to address CVE-2025-61730 ([PR](https://github.com/hashicorp/boundary/pull/6409))
* Go Cryptography dependency update to address CVE-2025-58181 and CVE-2025-47914
  ([PR](https://github.com/hashicorp/boundary/pull/6272))

## 0.19.3 (2025/07/10)
### New and Improved

* cli: Added `boundary connect mysql` command for connecting to MySQL targets.
  This new helper command allows users to authorize sessions against MySQL
  targets and automatically invoke a MySQL client with the appropriate
  connection parameters and credentials.
* Adds support to parse User-Agent headers and emit them in telemetry events
  ([PR](https://github.com/hashicorp/boundary/pull/5645)).

* Improved grants system performance by refactoring the IAM data model. In the previous version, Boundary always fetches all grants and grant scopes of a user to perform permissions checks. This refactor
   allows Boundary to only fetch the grants and grant scopes that are relevant to the current request, significantly improving performance for users with large numbers of roles and grant scopes.
  ([PR](https://github.com/hashicorp/boundary/pull/5846))

* ui: Sorting functionality added to aliases, groups, roles, scopes, targets, session recordings, sessions, users, auth methods, credential stores, and host catalogs resource tables.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2773))

### Bug fixes

* Fixed the `children` grant scope not behaving properly with `list-resolvable-aliases` ([PR](https://github.com/hashicorp/boundary/pull/5869/files)) ([PR](https://github.com/hashicorp/boundary/pull/5846))
* Fixed [issue 5003](https://github.com/hashicorp/boundary/issues/5003) where resource ID grants were prioritized over `ids=*` grants, causing grants to be overly restrictive under some circumstances. ([PR](https://github.com/hashicorp/boundary/pull/5877))

### Deprecations/Changes

* Modified parsing logic for various IP/host/address fields across Boundary.
  Notably, for some fields, Boundary previously required bracket-enclosed
  IPv6 addresses (eg: `[::1]`). With this change, if the provided address is
  just an IPv6 literal, enclosing the address in brackets is not valid.
  Additionally, an input address containing an IPv6 literal may be modified by
  Boundary to conform with RFC 5952.
  ([PR](https://github.com/hashicorp/boundary/pull/5599))

* Redundant grant scopes are no longer allowed. For example, if an org scope inherits a grant from the global scope, you cannot apply the same grant directly to the org scope. Passing the `-repair` flag to the `boundary database migrate` command will find and remove any redundant grant scopes in the database.
  ([PR](https://github.com/hashicorp/boundary/pull/5846))

## 0.19.2 (2025/05/08)
### New and Improved

* ui: Populate subject for OIDC account name displays.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2757)).
* ui: Improved performance when initially fetching large sets of resources.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2752)).
* ui: Improved search & filtering behavior when using search field.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2735)).

### Bug fixes

* Fixed an issue in the worker where closing an SSH channel failed to exit a
  loop, which would cause a massive spike in CPU usage over time. This change
  only affects Enterprise.
* ui: Fix an issue where the user could not change the key_type of a
  Vault SSH Certificate credential library.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2790)).

## 0.19.1 (2025/03/04)
### New and Improved

* Adds support for Azure Virtual Machine Scale Sets in the Azure plugin
  ([PR](https://github.com/hashicorp/boundary-plugin-azure/pull/22)).

## 0.19.0 (2025/02/10)
### New and Improved

* Introduces soft-delete for users within the client cache.
  ([PR](https://github.com/hashicorp/boundary/pull/5173)).
* GCP dynamic host catalog: Add dynamic host catalog support for
  discovering GCP Compute Engine VM Instances.
  ([PR](https://github.com/hashicorp/boundary/pull/5229)).
* The worker domain has been refactored to create clear domain functions for worker operations, improve readability and
maintainability of worker queries, and improve DB performance. ([PR](https://github.com/hashicorp/boundary/pull/5338)).
* Adds support for dual-stack networking for AWS operations.
  ([PR](https://github.com/hashicorp/boundary-plugin-aws/pull/52))
  * **Note**: As a consequence of updating AWS SDK dependencies to enable
    dual-stack support, this Boundary release may consume more memory. From our
    testing, the increase seems to be around 1.6x, however this
    may vary depending on your deployment architecture.
* The worker <-> controller communications have been refactored to improve performance
  and reliability at large scale. Workers older than v0.19.0 will remain supported
  until the release of v0.20.0, in accordance with
  [our worker/controller compatiblity policy](https://developer.hashicorp.com/boundary/docs/enterprise/supported-versions#control-plane-and-worker-compatibility).
* Add concurrency limit on the password hashing of all password auth methods.
  ([PR](https://github.com/hashicorp/boundary-plugin-aws/pull/5437)).

  This avoids bursty memory and CPU use during concurrent password auth method
  authentication attempts. The number of concurrent hashing operations
  can be set with the new `concurrent_password_hash_workers` configuration
  value in the controller stanza, or the new
  `BOUNDARY_CONTROLLER_CONCURRENT_PASSWORD_HASH_WORKERS` environment variable.
  The default limit is 1.
* ui: Improve worker filter workflow for targets, vault credential-stores, and storage-buckets. ([PR](https://github.com/hashicorp/boundary-ui/pull/2614)).

### Bug fixes

* Fix bug in applying BOUNDARY_MAX_RETRIES for boundary cli. Previously
  setting this environment variable would result in a max retries of 2,
  regardless of the value set.
  ([PR](https://github.com/hashicorp/boundary/pull/5385)).
* Fix bug in parsing IPv6 addresses. Previously setting a target address or the
  initial upstream address in the config file would result in a malformed value.
  ([PR](https://github.com/hashicorp/boundary/pull/5221)).
* Fix an issue where, when starting a session, the connection limit always displays 0.
  ([PR](https://github.com/hashicorp/boundary/pull/5396)).
* Fix bug which caused the `children` keyword not to apply the appropriate
  permissions for a number of resources.
    ([PR](https://github.com/hashicorp/boundary/pull/5418)).
* Fix bug where database transactions were not using the correct reader & writer functions
  and context.
    ([PR](https://github.com/hashicorp/boundary/pull/5522)).
* Remove unnecessary subquery from alias refresh
    ([PR](https://github.com/hashicorp/boundary/pull/5481)).

### Security

* Go Networking dependency update to address CVE-2024-45338 and GO-2024-3333
    ([PR])(https://github.com/hashicorp/boundary/pull/5405).
* Go Cryptography dependency update to address CVE-2024-45337
    ([PR](https://github.com/hashicorp/boundary/pull/5354)).

## 0.18.3 (2025/02/10) (Enterprise only)
### Bug fixes

* Fix bug where database transactions were not using the correct reader & writer functions
  and context.
    ([PR](https://github.com/hashicorp/boundary/pull/5522)).
* Remove unnecessary subquery from alias refresh
    ([PR](https://github.com/hashicorp/boundary/pull/5481)).

### Security

* Go Networking dependency update to address CVE-2024-45338 and GO-2024-3333
    ([PR])(https://github.com/hashicorp/boundary/pull/5406).
* Go Cryptography dependency update to address CVE-2024-45337
    ([PR](https://github.com/hashicorp/boundary/pull/5365)).

## 0.17.4 (2025/02/10) (Enterprise only)
### Bug fixes

* Fix bug where database transactions were not using the correct reader & writer functions
  and context.
    ([PR](https://github.com/hashicorp/boundary/pull/5522)).
* Remove unnecessary subquery from alias refresh
    ([PR](https://github.com/hashicorp/boundary/pull/5481)).

### Security

* Go Networking dependency update to address CVE-2024-45338 and GO-2024-3333
    ([PR])(https://github.com/hashicorp/boundary/pull/5528).
* Go Cryptography dependency update to address CVE-2024-45337
    ([PR](https://github.com/hashicorp/boundary/pull/5366)).

## 0.18.2 (2024/12/12)
### Bug fixes

* Fixed an issue where session recordings would fail when large numbers of
  sessions were created around the same time. ([PR](https://github.com/hashicorp/boundary-plugin-aws/pull/55))
* Fixed an issue where the controller would incorrectly handle HTTP requests
  and stop prematurely. ([PR](https://github.com/hashicorp/boundary/pull/5304))

## 0.17.3 (2024/12/12)
### Bug fixes

* Fixed an issue where session recordings would fail when large numbers of
  sessions were created around the same time. ([PR](https://github.com/hashicorp/boundary-plugin-aws/pull/55))
* Fixed an issue where the controller would incorrectly handle HTTP requests
  and stop prematurely. ([PR](https://github.com/hashicorp/boundary/pull/5304))

## 0.18.1 (2024/11/21)
### New and Improved

* Delete terminated sessions in batches to avoid long running jobs.
  ([PR](https://github.com/hashicorp/boundary/pull/5201))

### Bug fixes

* Fix an issue where users would lose access to managed groups if
  there are more than 10,000 managed groups in the auth method used.
  ([PR](https://github.com/hashicorp/boundary/pull/5242))
* Fix an issue where only the first 10,000 members of a managed group
  are returned when getting the managed group, and a similar issue where
  only the first 10,000 managed groups an account is part of is included
  when getting the account.
  ([PR](https://github.com/hashicorp/boundary/pull/5245))

## 0.18.0 (2024/10/01)
### New and Improved

* Add support for dynamic host catalog plugins running in Boundary workers:
  Boundary plugins that handle dynamic host catalog operations (such as the
  [AWS](https://github.com/hashicorp/boundary-plugin-aws/tree/main/plugin/service/host)
  and [Azure](https://github.com/hashicorp/boundary-plugin-azure) plugins) can
  now run on workers. ([PR](https://github.com/hashicorp/boundary/pull/5137))

* Dynamic host catalogs worker filter support (Enterprise and HCP Boundary
  only): Operators can now set a worker filter when creating a dynamic host
  catalog. When set, all of the plugin requests will be sent to the matching
  worker for processing. ([PR](https://github.com/hashicorp/boundary/pull/5137))

* AWS dynamic host catalogs `AssumeRole` authentication support: Operators can
  now set-up AWS dynamic host catalogs using Amazon's `AssumeRole`
  authentication paradigm by providing a valid Role ARN when creating the host
  catalog. ([PR](https://github.com/hashicorp/boundary/pull/5137) and
  [PR](https://github.com/hashicorp/boundary-plugin-aws/pull/49))

* Improved MinIO storage plugin compatibility with other services by dropping
  the checksum headers in `PutObject`.
  ([PR](https://github.com/hashicorp/boundary-plugin-minio/pull/23))

* ui: Add UI support for searching and pagination of aliases.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2498))

* ui: Add UI support for filtering and pagination of session recordings.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2502))

* ui: Improve multi-scope grants select/deselect process.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2435))

### Bug Fixes

* Prevented a data-race in Boundary's event logging system.
  ([PR](https://github.com/hashicorp/boundary/pull/5139))

* Update Storage Bucket type icon in Target view.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2503))

* Allow user to retry with authentication is pending with OIDC.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2512))

### Deprecations/Changes

* Remove deprecated `controllers` field from the worker config, which was deprecated in 0.9.0 for
`initial_upstreams`([PR](https://github.com/hashicorp/boundary/pull/5125))

## 0.17.2 (2024/09/25)

### New and Improved

* Improve performance of grants query by reducing the number of rows that need
  to be returned. ([PR](https://github.com/hashicorp/boundary/pull/5126))
* Add several indexes to database tables to improve performance of cascading
  deletes/updates to session tables.
  ([PR](https://github.com/hashicorp/boundary/pull/5126))
* Reorder indexes on several join tables to improve performance of grants query.
  ([PR](https://github.com/hashicorp/boundary/pull/5126))
* Make client cache sqlite database persistent between restarts of the client
  cache daemon. ([PR](https://github.com/hashicorp/boundary/pull/5126))
* Improve client cache performance by adding indexes, limiting results,
  and insuring only one refresh is running at a time for a given user and
  resource. ([PR](https://github.com/hashicorp/boundary/pull/5126))
* Add pagination support to client API and use pagination when caching
  resources in client cache.
  ([PR](https://github.com/hashicorp/boundary/pull/5101) and
  ([PR](https://github.com/hashicorp/boundary/pull/5107)

### Bug Fixes

* The Go API properly uses the passed in value for `WithRecursive` and
  `WithSkipCurlOutput` instead of always setting to true regardless of the
  passed-in value. ([PR](https://github.com/hashicorp/boundary/pull/5066))

## 0.17.1 (2024/08/21)

### New and Improved

* Add `GetDownstreamWorkersTimeout` config option which represents the period of
  time (as a duration) timeout for GetDownstreamWorkers call in
  DownstreamWorkerTicker. This is currently not documented and considered
  internal. ([PR](https://github.com/hashicorp/boundary/pull/5007))

### Bug Fixes

* Fixed issue where storage policies were not deleted when scopes are deleted
  ([PR](https://github.com/hashicorp/boundary/pull/5014))
* Contains Bug Fixes from 0.16.3

### Security

* Contains Security Fixes from 0.16.3

## 0.16.3 (2024/08/21)

### New and Improved

* Add `GetDownstreamWorkersTimeout` config option which represents the period of
  time (as a duration) timeout for GetDownstreamWorkers call in
  DownstreamWorkerTicker. This is currently not documented and considered
  internal. ([PR](https://github.com/hashicorp/boundary/pull/5007))

### Bug Fixes

* Minio large file support: Disable multipart uploads via minio to fix an issue
  where the file checksum is set incorrectly on each part of the upload, causing
  it to fail. This change fixes file uploads larger than 16MB and limits upload
  sizes to 5GB. ([PR](https://github.com/hashicorp/boundary/pull/5013)) and
  ([PR](https://github.com/hashicorp/boundary-plugin-minio/pull/21))
* Resolved an issue where session authorization was returning a `401` if the
  alias is non-existent or the alias does not resolve to anything. A `404`
  status code is now returned.
  ([PR](https://github.com/hashicorp/boundary/pull/5006)))

### Security

* curl (enterprise): The curl binary is no longer included in the published
  Docker container images for Boundary Enterprise to address the CVE-2024-7264
  vulnerability.
  [CVE-2024-7264](https://github.com/advisories/GHSA-97c4-2w4v-c7r8)

## 0.17.0 (2024/07/17)

### New and Improved

* SBC (Storage Bucket Credential): This release introduces, SBC, a resource that
represents credentials for authentication and authorization with an external
object store. There are two SBC types, managed secret and environmental.
([PR](https://github.com/hashicorp/boundary/pull/4933)),
([PR](https://github.com/hashicorp/boundary-plugin-minio/pull/18)) and
([PR](https://github.com/hashicorp/boundary-plugin-aws/pull/46))
  * SBC State: This release introduces, SBC State, which represents the ability
  for a worker to perform a specific action using the storage bucket. SBC
  permission types (write, read, & delete) represent an action that is required
  for the storage bucket to do as a routine task on an external object store.
  Each permission type has a permission state (ok, error, unknown).
  * SBC Worker Filtering: For protocol aware workers that require interaction
  with an external storage service, the workers will be filtered by the SBC
  state depending on the action and permission required.
* ui: Add multiple grant scope support for roles
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2388))
* ui: Add API tags support for workers and improve worker filtering for targets
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2393))
* Updated grpc to 1.61.1([PR](https://github.com/hashicorp/boundary/pull/4983))

### Bug Fixes

## 0.16.2 (2024/06/10)

### New and Improved

* Updated Minio plugin to allow for potential use with other S3-compatible
storage providers.
([PR](https://github.com/hashicorp/boundary-plugin-minio/pull/16)) and
([PR](https://github.com/hashicorp/boundary-plugin-minio/pull/17))

### Bug Fixes

* Fixed a bug where a worker credential rotation request suceeded on the
controller but the response to the worker was lost. This resulted in the
controller using a separate set of credentials than the worker, causing the
worker to be unable to connect to the controller. The fix implements the new
nodeenrollment library NodeIdLoader interface, which ensures that on store, if
worker NodeInformation has a previous key set, the worker will check and correct
its stored credential set to match. LodeNodeInformation was also updated to fix
a bug where in this split credential scenario, the current credential key was
assumed to be the incoming worker key, which caused the wrong key information to
be populated for the key id.
([PR](https://github.com/hashicorp/boundary/pull/4870))

### New and Improved

* Allow descriptions to contain newlines and other whitespace
  ([PR](https://github.com/hashicorp/boundary/pull/2599))
* Listed roles contain grant scope ID information
  ([PR](https://github.com/hashicorp/boundary/pull/4893))

### Deprecations/Changes

* The `grant_scope_id` field on roles, which was deprecated in 0.15.0, has been removed.
  ([PR](https://github.com/hashicorp/boundary/pull/4886))

## 0.16.1 (2024/05/30)

### New and Improved

* The observation tag was added to session recording and storage bucket proto messages for telemetry purposes. If you enable telemetry and observation events, Boundary will now collect data about session recording and storage buckets.
([PR](https://github.com/hashicorp/boundary/pull/4824)) and ([PR](https://github.com/hashicorp/boundary/pull/4825))

### Deprecations/Changes

* The `boundary daemon` command has been deprecated in favor of the new
  `boundary cache` command. The behavior remains the same. The `boundary search`
  command is unchanged.
  ([PR](https://github.com/hashicorp/boundary/pull/4808))
* The include_terminated field in the list sessions request will be removed
  in an upcoming release. After the deprecation process is complete and the
  field is removed terminated sessions will be returned
  in all list session responses unless filtered out using the filter field.
  ([PR](https://github.com/hashicorp/boundary/pull/4602))

### Bug Fixes

* Fix a dead lock issue where the controller could get stuck with all of its
  available database connections being stuck in `idle in transaction`.
  If a controller is configured to have a `max_open_connections`, and was under
  sufficient load in the form of requests from workers interacting with
  sessions, like in the form of authorizing new session connections, the
  controller could get stuck after consuming all of the database connections,
  leaving them in the `idle in transaction` state. This was due to a
  combination of issues, including the lack of a request timeout for worker to
  controller grpc requests, and the session repository attempting to use a
  separate database connection to retrieve a kms.Wrapper after already starting
  a database transaction. The fixes move these kms operations outside of the
  transaction and set a max request duration for the grpc requests based on
  the cluster's listener configuration.
  ([PR](https://github.com/hashicorp/boundary/pull/4803) and
  [PR](https://github.com/hashicorp/boundary/pull/4805))
* LDAP account attribute maps. Account attribute maps have been supported since
  the introduction of LDAP authentication, however a bug was present where we
  wouldn't take those into account upon authenticating (when receiving the
  information from the LDAP server). This is now resolved
  ([PR]((https://github.com/hashicorp/boundary/pull/4788))).

## 0.16.0 (2024/04/30)

### New and Improved

* Target aliases have been added: You can now create an alias for a target. In
  most situations where you would use a target id, you can now instead use the
  alias value. Create an alias with `boundary aliases create target -value
  example.boundary -destination-id ttcp_1234567890` and connect to a target
  using an alias using `boundary connect example.boundary`
* Worker local storage state: Self managed workers that are configured to be
  used for session recordings will report the state of the its disk space. To
  learn more about this new feature, refer to the
  [documentation](http://developer.hashicorp.com/boundary/docs/configuration/session-recording/create-storage-bucket#local-storage).
* MinIO storage plugin: You can now create a storage bucket that allows Boundary
  to interoperate with a MinIO cluster for Session Recording storage. This
  includes some added functionality such as credential rotation and credential
  management. To learn more about the plugin, refer to the
  [readme](https://github.com/hashicorp/boundary-plugin-minio?tab=readme-ov-file#minio-plugin-for-hashicorp-boundary).
  *Note:* Due to a library incompatibility, this release is not yet compatible
  with the `netbsd` operating system. Please refer to the following
  [documentation](http://developer.hashicorp.com/boundary/docs/configuration/session-recording/create-storage-bucket)
  to learn how to create a storage bucket.
* ui: Add UI support for filtering and pagination
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2237))
* ui: Add UI support for MinIO (Enterprise and HCP Boundary only)
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2248))

### Added dependency

* postgres `citext` dependency added to enable aliases to be globally unique in
  a case insensitive way.

## 0.15.4 (2024/04/09)

### Security

* Go version bumped to 1.22.2 to address
  [CVE-2023-45288](https://github.com/advisories/GHSA-4v7x-pqxf-cx7m)

## 0.15.3 (2024/03/21)

### Bug Fixes

* Fix a nil pointer error in the client cache daemon when a refresh was forced
  performing a boundary search.
  ([PR](https://github.com/hashicorp/boundary/pull/4503))
* workers: Workers connecting over high latency connections, or to controllers
  with high latency between the controller and the database, could time out and
  throw errors that may not have been recoverable if it was during initial
  registration ([PR](https://github.com/hashicorp/boundary/pull/4535))
* Resolved an issue introduced in 0.14 where, after successfully deleting an AWS S3
  Storage Bucket with credential rotation enabled, Boundary could not delete the
  associated IAM Access Key resource

### New and Improved

* templating: A new templating function `coalesce` can be used to match a
  template against multiple possible values, returning the first non-empty
  value. As an example, this can be used in a credential library to allow a
  username value that might be comprised of a name or login name depending on
  the auth method, e.g. `{{ coalesce .Account.Name .Account.LoginName}}`
  ([PR](https://github.com/hashicorp/boundary/pull/4492)))

## 0.15.2 (2024/03/11)

### Bug Fixes

* Go version bump 1.21.8 to address (CVE-2024-24783, CVE-2023-45290,
  CVE-2023-45289, CVE-2024-24785, CVE-2024-24784)

* Protobuf Go update to address [CVE-2024-24786](https://github.com/advisories/GHSA-8r3f-844c-mc37)

## 0.15.1 (2024/02/28)

### Bug Fixes

* cli: Update proxy listener to not close when the number of connections left
  for the session is zero. The listener will refuse new connections when the
  number of connections left is zero but existing connections will be active.
  This fixes a CLI client issue where sessions with max connection count
  configured were closed when the number of connections left hit 0.
  ([Issue](https://github.com/hashicorp/boundary/issues/4364),
  ([PR](https://github.com/hashicorp/boundary/pull/4389)))
* Fix issue where the websocket connection was throwing closing errors during
  the session teardown.
  ([PR](https://github.com/hashicorp/boundary/pull/4389))

### New and Improved

* feat: support added for tracking and reporting monthly active users for
  the purpose of billing. It adds a new API endpoint,
  `/v1/billing:monthly-active-users` and new cli command,
  `boundary billing monthly-active-users` that can be used to view the monthly
  active user counts.

## 0.15.0 (2024/01/30)

### Deprecations/Changes

* Per the note in Boundary 0.13.0, the previous `kms` worker method has been
  removed. Since 0.13.0, unless the `use_deprecated_kms_auth_method` value was
  set on the worker config, the new `kms` mechanism was already being used; this
  is simply no longer an available option.
* Per the notes in Boundary 0.12.0 and 0.14.0, it is now an error if an address
  on a host or target contains a port. As of this release, this restriction also
  affects existing addresses (not just creation/updating via the API) so any
  existing addresses containing a port will not be able to be used as part of a
  target's session authorization call.
* The `grant_scope_id` field on roles is now deprecated in favor of the multiple
  grant scope support.
* Per the note in Boundary 0.13.1, the `id` field in grants has changed to `ids`
  which allows multiple ids to be included; existing grants submitted to
  Boundary will continue to work, but grants using "id" can no longer be added
  to or set on a role.
* All list endpoints except workers now return the first 1000 items instead
  of all items if no parameters are provided. The number of items returned can
  be configured through the new controller configuration value `max_page_size`.
  The Admin UI, CLI and api package automatically paginate results.

### New and Improved

* Multiple grant scopes in roles: Roles now support multiple grant scopes, along
  with the special values `this`, `children` (global/org only) to apply to all
  direct children of a scope, and `descendants` (global only) to apply to all
  descendants of a scope. These use the new actions `add-grant-scopes`,
  `set-grant-scopes`, and `remove-grant-scopes` on roles. For now the
  `grant_scope_id` field on roles will continue to be able to be set, which will
  set a single grant scope, but this capability is now deprecated.
* Policies (Enterprise and HCP Boundary only): This release introduces Policies, a
  Boundary resource that represents a Governance Policy to enforce. The first
  implementation targets Storage Policies, which enables administrators to automate
  the process of retention and deletion of Session Recordings, ensuring that they're only
  retaining data that is explicitly required from a security/compliance perspective.
  * ui: Add full UI support for Storage Policies managing the lifecycle of Session Recordings.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/2089))
* New generic commands `read`, `update`, and `delete` have been added. These
  allow operating on resources by directly specifying the ID of the resource as
  the next parameter (e.g. `boundary update ttcp_1234567890`). Subtypes do not
  need to be specified (e.g. that command is equivalent to `boundary targets
  update tcp -id ttcp_1234567890`), and any flags given after the ID are passed
  through to the type-specific subcommand. Once the ID has been entered,
  autocomplete is also supported.
  ([PR](https://github.com/hashicorp/boundary/pull/3992))
* The `key_id` parameter within SSH Certificate Credential Libraries now accepts
  the use of templated parameters
  ([PR](https://github.com/hashicorp/boundary/pull/4215))
* List endpoint pagination: All list endpoints except workers now support pagination.
  * api: All list endpoints except workers have added support for pagination.
    The api package automatically paginates until the end of the results. The new
    `WithListToken`` option can be used to request a list of updated and deleted resources
    relative to the last result received.
  * config: add new controller field `max_page_size` for controlling the default and max size
    of pages when paginating through results.
* New command `search` has been added allowing quick searching of targets or
  sessions. It utilizes a client side cache also added in this release. The
  client side cache starts itself automatically in the background when successfully
  executing any command that communicates with a Boundary controller. To disable
  the client cache from starting automatically set the
  `BOUNDARY_SKIP_CACHE_DAEMON` environment variable or pass the
  `-skip-cache-daemon` flag when running a command that may start it.
  Commands `daemon start`, `daemon stop`, `daemon status`, and `daemon add-token`
  were added to help manage the cache. The cache does not currently work with
  Boundary instances that require the use of client side certs.

## 0.14.3 (2023/12/12)

### New and Improved

* Added the ability to enforce rate limits on the Controller API. This version
  enables rate limits by default. For details on the default rate limits,
  how to configure rate limits, and how to disable rate limiting see the
  noted PR. ([PR](https://github.com/hashicorp/boundary/pull/4092))
* Add support for OIDC prompts. Using prompts, the Relying Party (RP) can
  customize the authentication and authorization flow to suit their specific
  needs and improve the user experience. [OIDC Authentication request]
  (https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) server.
  ([PR](https://github.com/hashicorp/boundary/pull/4053))

### Bug Fixes

* Update go-kms-wrapping/extras/kms dependency to allow external wrappers
  without a key id to be used within a KMS config stanza.  Note: this fix allows
  GCP KMS keys to be again with Boundary, which had stopped working in v0.13.0.
  ([PR](https://github.com/hashicorp/boundary/pull/4058))

* Two Vault client settings were not being properly used when constructing a
  Vault client. ([PR](https://github.com/hashicorp/boundary/pull/3973))

  The `TLS Skip Verify` setting was only being set if a `CA Cert` was also
  configured. This fix sets the `TLS Skip Verify` when configured regardless of
  other settings.

  The `TLS Server Name` setting was never being set. Bad programmers. This fix
  now sets it on the Vault client if the Vault Credential Store has been
  configured to use a value for this setting.

### Security

* deps: Bump Go version to v1.21.5. This is to address multiple security
  vulnerabilities. Most notable for boundary is a fix in net/http to limit
  chunked data overhead. See https://groups.google.com/g/golang-announce/c/iLGK3x6yuN

## 0.14.2 (2023/11/2)

### New and Improved

* Expose Valid Principals for Vault SSH Signed Certs: Allow users to add
  additional valid principals when creating a vault ssh signed cert credential
  library ([PR](https://github.com/hashicorp/boundary/pull/3791)).

### Bug Fixes

* High CPU consumption: A background GRPC connection state check caused high CPU
  utilization. This was caused by a long running loop that was checking for GRPC
  connection state changes between a worker and an upstream connection address.
  The loop was not correctly waiting for GRPC connection state changes before
  running. The issue was fixed by correctly updating the state that determines
  when the loop in GRPC connection state check should run.
  ([PR](https://github.com/hashicorp/boundary/pull/3884))
* LDAP auth methods: Fix encoding of mTLS client key which prevented Boundary
  from making mTLS connections to an LDAP server
  ([Issue](https://github.com/hashicorp/boundary/issues/3927),
  [PR](https://github.com/hashicorp/boundary/pull/3929)).

## 0.14.1 (2023/10/17)

### Security

* deps: Bump Go version to v1.21.3; gRPC to v1.58.3; golang.org/x/net to
  v0.17.0. This is to address a security vulnerability in the HTTP stack where a
  malicious HTTP/2 client which rapidly creates requests and immediately resets
  them can cause excessive server resource consumption.

## 0.14.0 (2023/10/10)

### Deprecations/Changes

* Per the note in Boundary 0.12.0, the `vault` credential library subtype has
  now been removed in favor of `vault-generic`. For example, instead of
  `boundary credential-libraries create vault`, you must use `boundary
  credential-libraries create vault-generic`.
* Per the note in Boundary 0.12.0, errors returned from the cli when using the
  `-format=json` option will now only use the `status_code` field. The `status`
  field has been removed.
* Per the note in Boundary 0.12.0, targets require a default port value. Ports
  defined as part of a host address were ignored but allowed as part of a target
  definition; from 0.14.0 onwards, any port defined on a host address will now
  become an error.
* Targets: Per the note in Boundary 0.10.10, target Application Credentials has
  been renamed to Brokered Credentials. `application-credential-source` has been
  removed as a field. `brokered-credential-source` should be used instead.
  ([PR](https://github.com/hashicorp/boundary/pull/3728), [deprecated
  changelog](#0100-20220810)).

### New and Improved

* cli: Add support for specifying a command that will be executed on the remote host when
  using the `boundary connect ssh` subcommand.
  ([Issue](https://github.com/hashicorp/boundary/issues/3631),
  [PR](https://github.com/hashicorp/boundary/pull/3633)).
* feat: add API support for additional LDAP auth method fields:
  `maximum_page_size` and `dereference_aliases`
  ([PR](https://github.com/hashicorp/boundary/pull/3679)).
* feat: add worker upstream connection status to ops health check
  ([PR](https://github.com/hashicorp/boundary/pull/3650)).
* feat: allow HCP cluster id to be sourced from file or env variable
    ([PR](https://github.com/hashicorp/boundary/pull/3709)).
* feat: add support for telemetry events via flag or Boundary configuration
  (requires observation events to be enabled). Deny filter now filters
  coordination worker status from observation events by default. (This behavior
  is overridden by any user specified allow or deny filters)
  ([PR](https://github.com/hashicorp/boundary/pull/3753)).
* ui: Add full UI support for LDAP auth method
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1782))
* ui: Add new attribute fields to storage bucket to support the assume role service in AWS.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1901))

### Bug Fixes

* LDAP auth methods: allow bind-dn and bind-password to be updated
  independently. ([PR](https://github.com/hashicorp/boundary/pull/3511))
* targets: Fix address field not being populated if the number of targets on a
  list returns more than 10000 entries
  ([PR](https://github.com/hashicorp/boundary/pull/3644))
* cli: Fix issue when using the `authenticate` command against a password auth
  method on Windows where the password would be swallowed when the login name is
  submitted ([PR](https://github.com/hashicorp/boundary/pull/3800))
* worker: Fix an issue that could cause intermittent startup issues on slow
  systems ([PR](https://github.com/hashicorp/boundary/pull/3803))
* cli: Remove websocket max message size. This fixes issues where large message
  sizes are sent to the client from a worker which resulted in the connection
  being terminated, as is the case with an scp download when using an SSH
  Target. ([PR](https://github.com/hashicorp/boundary/pull/3808))

## 0.13.5 (2023/12/12) (Enterprise and HCP Boundary only)

### Security

* deps: Bump Go version to v1.21.5. This is to address multiple security
  vulnerabilities. Most notable for boundary is a fix in net/http to limit
  chunked data overhead. See https://groups.google.com/g/golang-announce/c/iLGK3x6yuN

## 0.13.1 (2023/07/10)

### New and Improved

* roles: In grants, the `id` field has been changed to `ids` (but `id` will
  still be accepted for now, up until 0.15.0). In the `ids` field, multiple IDs
  can now be specified in a grant, either via commas (text format) or array
  (JSON format). ([PR](https://github.com/hashicorp/boundary/pull/3263)).
* dev environment: When running `boundary dev` the initial LDAP auth-method with an
  ID of `amldap_1234567890` is now in a public-active state, so it will be returned
  in the response from `boundary auth-methods list`

### Deprecations/Changes

* Grants can now accept more than one ID per grant string (or entry in JSON) via
  the `ids` parameter. In 0.15.0 the ability to add new grants via the `id`
  parameter will be removed.

### Bug Fixes

* PKI worker authentication: A worker authentication record can be stored more than once, if it matches the
  existing record for that worker auth key ID. Fixes an edge case where a worker attempted authorization
  and the controller successfully stored the worker auth record but went down before returning authorization
  details to the worker. ([PR](https://github.com/hashicorp/boundary/pull/3389))
* LDAP managed groups: adding/setting/removing a principal to a role now works
  properly when it's an LDAP managed group.
  ([PR](https://github.com/hashicorp/boundary/pull/3361) and
  [PR](https://github.com/hashicorp/boundary/pull/3363))

## 0.13.0 (2023/06/13)

### New and Improved

* SSH Session Recordings (Enterprise and HCP Boundary only): SSH targets can now
  be configured to record sessions. Recordings are signed and stored in a
  Storage Bucket. Recordings can be played back in the admin UI.
  * Storage Buckets: This release introduces Storage Buckets, a Boundary
    resource that represents a bucket in an external object store. Storage
    Buckets can be defined at the global or org scope. When associated with an
    SSH target, the storage bucket is used to store session recordings. This
    release includes support for AWS S3 only.
  * BSR (Boundary Session Recording) file format: BSR is a new specification
    that defines a hierarchical directory structure of files and a binary file
    format. The contents of a BSR include all data transmitted between a user
    and a target during a single session, relevant session metadata and summary
    information. The BSR also includes checksum and signature files for
    cryptographically verifying BSR contents, and a set of KMS wrapped keys for
    use in BSR verification. The BSR format is intended to be extensible to
    support various protocols. With this release BSR supports the SSH protocol.
    It also supports converting an SSH channel recording into an
    [asciicast](https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md)
    format that is playable by asciinema.
  * To learn more about this new feature, refer to the
    [documentation](http://developer.hashicorp.com/boundary/docs/configuration/session-recording).
* KMS workers: KMS workers now have feature parity with PKI workers (they
  support multi-hop and Vault private access) and support separate KMSes for
  authenticating downstreams across different networks. See the [worker
  configuration
  documentation](https://developer.hashicorp.com/boundary/docs/configuration/worker)
  for more information. ([PR](https://github.com/hashicorp/boundary/pull/3101))
* roles: Perform additional validity checking on grants at submission time
  ([PR](https://github.com/hashicorp/boundary/pull/3081))
* targets: The new `default_client_port` field allows specifying the default
  port to use on the client side when connecting to a target, unless overridden
  by the client via `-listen-port`
  ([PR](https://github.com/hashicorp/boundary/pull/2767))
* cli/api/sdk: New LDAP auth method type added with support for create, read,
  update, delete, and list (see new cli `ldap` subcommands available on CRUDL
  operations for examples), as well as the ability to authenticate against it
  via the SDK, CLI, admin UI, and desktop client.
  ([PR](https://github.com/hashicorp/boundary/pull/2912))
* ui: Display external names when listing dynamic hosts ([PR](https://github.com/hashicorp/boundary-ui/pull/1664))
* ui: Add support for LDAP authentication ([PR](https://github.com/hashicorp/boundary-ui/pull/1645))
* Dynamic Host Catalog: You can now view the AWS or Azure host name when listing hosts in CLI,
  admin console, and desktop client. ([PR](https://github.com/hashicorp/boundary/pull/3074))
* Add configuration for license reporting (Enterprise only)

### Deprecations/Changes

* With the introduction of the new KMS variant for worker registration (as
  described below), using the deprecated behavior requires opting-in. This is
  only recommended if compatibility with pre-0.13 workers using the KMS auth
  method is required. Requiring opting in removes some potentially confusing
  behavior for deciding when to use the old versus new mechanism. To opt in, add
  `use_deprecated_kms_auth_method = true` to the `worker` config block. Note
  that if a 0.13+ worker using KMS connects to a 0.13+ controller using KMS, the
  transition to the new method will happen automatically. To go back to the old
  method after that will require the worker to be deleted and re-added with the
  `use_deprecated_kms_auth_method` config field specified.
* When grants are added to roles additional validity checking is now performed.
  This extra validity checking is designed to reject grants that are not
  [documented grant
  formats](https://developer.hashicorp.com/boundary/docs/concepts/security/permissions/permission-grant-formats)
  or are for combinations of IDs and types that cannot actually be used
  together. These previously would have been accepted without error but would
  never result in permissions being granted, causing confusion. As a result,
  attempting to write such grants into roles may now result in an error; the
  error message gives hints for resolution.
* `WithAutomaticVersioning` for auth tokens in Go SDK: this option was
  incorrectly being generated for auth token resources, which do not support
  versioning. This is technically a breaking change, but it was a no-op option
  anyways that there was no reason to be using. It has now been removed.
* Plugins: With the introduction of the storage plugin service, the Azure and AWS Host plugin
  repositories have been renamed to drop the `host` element of the repository name:

   - https://github.com/hashicorp/boundary-plugin-host-aws -> https://github.com/hashicorp/boundary-plugin-aws
   - https://github.com/hashicorp/boundary-plugin-host-azure -> https://github.com/hashicorp/boundary-plugin-azure

  Similarly the `plugins/host` package has been renamed to `plugins/boundary`
  ([PR1](https://github.com/hashicorp/boundary/pull/3262),
  [PR2](https://github.com/hashicorp/boundary-plugin-aws/pull/24),
  [PR3](https://github.com/hashicorp/boundary-plugin-azure/pull/12),
  [PR4](https://github.com/hashicorp/boundary/pull/3266)).
* PostgreSQL 12 or greater is now required. PostgreSQL 11 is no longer
  supported.

### Bug Fixes

* targets: `authorize-session` now works properly when using a target's name as
  the identifier and the target name contains one or more slashes
  ([PR](https://github.com/hashicorp/boundary/pull/3249))
* resource listing: API requests to list a resource (targets, sessions, users,
  etc) now properly return all resources the callers has appropriate permission
  to list ([PR](https://github.com/hashicorp/boundary/pull/3278))
* sessions: Fix a bug that contributed to slow response times when listing
  sessions that had a large number of connections
  ([PR](https://github.com/hashicorp/boundary/pull/3280))
* ui: Fix `client secret` bug for OIDC authentication methods([PR](https://github.com/hashicorp/boundary-ui/pull/1698))
* ui: Fix linking to a Host from the Host Set screen of a Dynamic Host Catalog ([PR](https://github.com/hashicorp/boundary-ui/pull/1659))

## 0.12.3 (2023/05/26)

Note: As this issue currently only affected HCP Boundary customers, there is no
open-source release of 0.12.3; the same fixes will be in 0.13.0 OSS.

### Bug Fixes

* workers: A bug in PKI worker auth rotation could mean that after a rotation
  the controller (or upstream worker) and downstream worker side could pick
  different certificate chains for authentication, with the only remedy being to
  re-authorize the workers. This has been fixed. If this bug was previously hit,
  in some specific cases updating only the worker to 0.12.3 will fix it;
  otherwise reauthorization will be necessary.

## 0.12.2 (2023/04/04)

### Security

* Boundary now uses Go 1.19.8 to address CVE-2023-24536. See the
  [Go announcement](https://groups.google.com/g/golang-announce/c/Xdv6JL9ENs8) for
  more details.

## 0.12.1 (2023/03/13)

### Bug Fixes

* cli: Fix fallback parsing of un-typed credentials for `boundary connect`.
  When using a vault credential library with no credential type set, boundary
  will perform a best effort attempt to parse any brokered credentials. If the
  credentials are successfully parsed, they can be used by the subprocess
  spawned when using the connect subcommands, i.e. `ssh` or `psql`. With the
  change to the vault credential library subtype, this fallback parsing would
  fail. Note that if the credential library has a credential type, by using
  `-credential-type` when creating the credential library, the credential was
  correctly parsed. This fallback parsing is now fixed, but in order to support
  older clients, credential libraries will need to be recreated with a
  credential type. [PR](https://github.com/hashicorp/boundary/pull/2989)
* ui: Fix credential library not saving correctly when trying to save it as a
  generic secrets type. ([PR](https://github.com/hashicorp/boundary-ui/pull/1640))
* sessions: Fix tofu token retrieval. ([PR](https://github.com/hashicorp/boundary/pull/3064))

## 0.12.0 (2023/01/24)

### Deprecations/Changes

* In Boundary 0.9.0, targets were updated to require a default port value. This
  had been the original intention; it was a mistake that it was optional.
  Unfortunately, due to a separate defect in the update verification logic for
  static hosts, it was possible for a host to be updated (but not created) with
  a port. This meant that targets could use ports attached to host addresses,
  which was not the intention and leads to confusing behavior across different
  installations. In this version, updating static hosts will no longer allow
  ports to be part of the address; when authorizing a session, any port on such
  a host will be ignored in favor of the default port on the target. In Boundary
  0.14.0, this will become an error instead. As a consequence, it means that the
  fallback logic for targets that did not have a default port defined is no
  longer in service; all targets must now have a default port defined.
* With the introduction of `vault-ssh-certificate` credential libraries, the
  `vault` credential library subtype is being renamed to `vault-generic` to
  denote it as a credential library that can be used in a generalized way to
  issue credentials from vault. Existing credential libraries with the
  subtype of `vault` will be updated to `vault-generic`. The subtype of
  `vault` will still be accepted as a valid subtype in API requests to the
  credential libraries endpoints, but is deprecated. Instead `vault-generic`
  should be used. In addition the `boundary credential-libraries create
  vault` and `boundary credential-libraries update vault` subcommands will
  still function, but are deprecated. Instead `boundary credential-libraries
  create vault-generic` and `boundary credential-libraries update
  vault-generic` should be used. Also note that any credential library created
  using the subtype of `vault`, either via the API or via the deprecated
  subcommand, will have the subtype set to `vault-generic`. The deprecated
  subtype and subcommands will be removed in boundary 0.14.0, at which point
  `vault-generic` must be used.
* In Boundary 0.1.8 using the `-format=json` option with the cli would provide
  a `status_code` for successful API requests from the cli. However, in the
  case where an error was returned, the JSON would use `status` instead. This
  inconsistency has been fixed, with `status_code` being used in both cases.
  For error cases `status` will still be populated, but is deprecated and will
  be removed in 0.14.0.

### New and Improved

* Direct Address Targets: You can now set an address directly on a target,
  bypassing the need for host catalogs, host sets and hosts.
  ([PR](https://github.com/hashicorp/boundary/pull/2613))
* Custom Response Headers: Adds ability to set api and ui response headers based
  on status code. Includes default secure CSP and other headers.
  ([PR](https://github.com/hashicorp/boundary/pull/2587))
* metrics: Adds accepted connections and closed connections counters to keep track
  downstream connections for worker and controller servers.
  ([PR](https://github.com/hashicorp/boundary/pull/2668))
* Egress and Ingress worker filters: The target `worker_filter` field has been deprecated and
 replaced with egress and ingress worker filters. Egress worker filters determine which workers are
 used to access targets. Ingress worker filters (HCP Boundary only) determine which workers are
 used to connect with a client to initiate a session. ([PR](https://github.com/hashicorp/boundary/pull/2654))
* Multi-Hop Sessions (HCP Boundary only): Multi-hop PKI workers can communicate with each other to serve
 2 primary purposes: authentication and session proxying. This results in the ability to chain
 multiple workers together to access services hidden under layers of network security. Multi-hop
 workers can also establish a TCP session through multiple workers, with the ability to reverse
 proxy and establish a connection.
* Vault SSH certificate credential library: A new credential library that uses
  the vault ssh secret engine to generate ssh private key and certificates. The
  library can be used as an injected application credential source for targets
  that support credential injection. ([PR](https://github.com/hashicorp/boundary/pull/2860))
* ui: Add support for managed groups in add-principals list.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1548))

### Bug Fixes

* plugins: Ignore `SIGHUP` sent to parent process; some init systems, notably
  `dumb-init`, would pass them along to the child processes and cause the
  plugin to exit ([PR](https://github.com/hashicorp/boundary/pull/2677))
* data warehouse: Fix bug that caused credential dimensions to not get
    associated with session facts ([PR](https://github.com/hashicorp/boundary/pull/2787)).
* sessions: Fix two authorizeSession race conditions in handleProxy. ([PR](https://github.com/hashicorp/boundary/pull/2795))
* cli: When using `-format=json` the JSON was inconsistent in how it reported
  status codes. In successful cases it would use `status_code`, but in error
  cases it would use `status`. Now `status_code` is used in both cases. In
  error cases `status` is still populated, see the deprecations above for
  more details. ([PR](https://github.com/hashicorp/boundary/pull/2887))
* database: Add job that automatically cleans up completed runs in the `job_run` table.
  ([PR](https://github.com/hashicorp/boundary/pull/2866))
* core: Linux packages now have vendor label and set the default label to HashiCorp.
  This fix is implemented for any future releases, but will not be updated for historical releases.

## 0.11.2 (2022/12/09)

### Security

* Boundary now uses Go 1.19.4 to address security vulnerability (CVE-2022-41717) See the
  [Go announcement](https://groups.google.com/g/golang-announce/c/L_3rmdT0BMU) for
  more details.

## 0.11.1 (2022/11/30)

### New and Improved

* Vault Parameter Templating: In `vault` credential libraries, the paths and any
  POST bodies can contain templated parameters using Go template syntax (similar
  to Consul-Template). The following template parameters are supported (note
  that account values are tied to the account associated with the token making
  the call):
    * `{{ .User.Id }}`: the user's ID
    * `{{ .User.Name }}`: the user's name (from the user resource)
    * `{{ .User.FullName }}`: the user's name (from the account corresponding to
    the primary auth method in the user's scope; this may not be populated or
    maybe different than the account name in the template)
    * `{{ .User.Email }}`: the user's email address (same caveat as `FullName`)
    * `{{ .Account.Id }}`: the account's ID
    * `{{ .Account.Name }}`: the account's name (from the account resource)
    * `{{ .Account.LoginName }}`: the account's login name (if used by that type
    of account)
    * `{{ .Account.Subject }}`: the account's subject (if used by that type
    of account)
    * `{{ .Account.Email }}`: the account's email (if used by that type
    of account)

    Additionally, there is currently a single function that strips the rest of a
    string after a specified substring; this is useful for pulling an user/account name from an email address. In the following example it uses the account email can be any other parameter:

    * `{{ truncateFrom .Account.Email "@" }}`: this would turn `foo@example.com` into `foo`
* Per-scope key lifecycle management: You can now manage the lifecycles of both Key
  Encryption Keys (KEKs) and Data Encryption Keys (DEKs) using the new key rotation
  and key version destruction functionality. To learn more about this new feature,
  refer to the
  [documentation](https://developer.hashicorp.com/boundary/docs/secure/encryption/data-encryption).

  Upgrade notice: If the Database purpose DEK for a scope is destroyed, you must use
  the API to cancel any sessions that predate the upgrade.
  ([PR](https://github.com/hashicorp/boundary/pull/2477))
* session: The amount of bytes received and transmitted over a session
  is now recorded and persisted. ([PR](https://github.com/hashicorp/boundary/pull/2503))

### Bug Fixes

* accounts: Deleted auth accounts would still show up as being associated with a
  User when reading the User
  ([PR](https://github.com/hashicorp/boundary/pull/2528))
* sessions: Fix workers not being in random order when returned to clients at
  `authorize-session` time, which could allow one worker to bear the majority of
  sessions ([PR](https://github.com/hashicorp/boundary/pull/2544))
* workers: In some error conditions when sending status to controllers, errors
  could be written to stdout along with a message that they could not
  successfully be evented instead of being written to the event log
  ([PR](https://github.com/hashicorp/boundary/pull/2544))
* workers: Fixed a panic that can happen in certain situations
  ([PR](https://github.com/hashicorp/boundary/pull/2553))
* sessions: Fixed a panic in a controller when a worker is deleted while
  sessions are ongoing ([PR](https://github.com/hashicorp/boundary/pull/2612))
* sessions: Fixed a panic in a worker when a user with an active
  session is deleted ([PR](https://github.com/hashicorp/boundary/pull/2629))
* sessions: Fixed a bug where reading a session after its associated project
  had been deleted would result in an error
  ([PR](https://github.com/hashicorp/boundary/pull/2615))
* config: Fixed a bug where supplying multiple KMS blocks with the same purpose
  would silently ignore all but the last block
  ([PR](https://github.com/hashicorp/boundary/pull/2639))

### Deprecations/Changes

* In order to standardize on the templating format, [templates in
  grants](https://developer.hashicorp.com/boundary/docs/concepts/security/permissions/permission-grant-formats#templates)
  now are documented to use the new capitalization and format; however, the
  previous style will continue to work.

## 0.11.0 (2022/09/27)

### Known Issues

* PKI workers in past versions did not store a prior encryption key, and a bug
  prior to 0.11.0 meant that auth rotations could happen more frequently than
  expected. This could cause some race issues around rotation time. However,
  there was another issue where a past worker authentication record could be
  looked up for some operations instead of the current one, made more likely by
  the too-frequent rotations. In 0.11.0 we attempt to ensure that the record
  that remains on upgrade is the most current one, but it is possible that the
  wrong one is chosen, leading to a failure for the worker to authenticate or
  for some operations to consistently fail. In this case, the worker will need
  to be deleted and re-authorized. We apologize for any issues this causes and
  this should be remedied going forward.

### Bug Fixes

* scopes: Organizations could be prevented from being deleted if some resources
  remained ([PR](https://github.com/hashicorp/boundary/pull/2465))
* workers: Authentication rotation could occur prior to the expected time
  ([PR](https://github.com/hashicorp/boundary/pull/2484))
* workers: When looking up worker authentication records, an old record could be
  returned instead of the new one, leading to errors for encryption or
  decryption operations ([PR](https://github.com/hashicorp/boundary/pull/2495))

### New and Improved

* vault: (HCP Boundary only): Private Vault clusters can be used with HCP Boundary by using PKI workers
  deployed in the same network as a private cluster. Tags are used to control which PKI workers can manage private Vault
  requests by specifying a `worker_filter` attribute when configuring a Vault credential store.
* credentials: There is now a `json` credential type supported by `static`
  credential stores that allows submitting a generic JSON object to Boundary for
  use with credential brokering workflows
  ([PR](https://github.com/hashicorp/boundary/pull/2423))
* ui: Add support for worker management
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1229))
* ui: Add support for PKI worker registration
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1244))
* ui: Add support for Static Credential Stores
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1193))
* ui: Add support for Username & Password Credentials
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1205))
* ui: Add support for Username & Key Pair Credentials
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1266))
* ui (HCP Boundary only): SSH Target creation along with injected application
  credential support ([PR](https://github.com/hashicorp/boundary-ui/pull/1027))
* ui (HCP Boundary only): Update vault credential stores to support private
  vault access ([PR](https://github.com/hashicorp/boundary-ui/pull/1318))
* ui: Improve quick setup wizard onboarding guide resource names
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1328))
* ui: Updates to host catalog and host set forms and “Learn More” links
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1342))
* workers: Added the ability to read and reinitialize the Worker certificate
  authority ([PR1](https://github.com/hashicorp/boundary/pull/2312),
  [PR2](https://github.com/hashicorp/boundary/pull/2387))
* workers: Return the worker Boundary binary version on worker list and read
  ([PR](https://github.com/hashicorp/boundary/pull/2377))
* workers: Addition of worker graceful shutdown, triggered by an initial
  `SIGINT` or `SIGTERM` ([PR](https://github.com/hashicorp/boundary/pull/2455))
* workers: Retain one previous encryption/decryption key after authentication
  rotation ([PR](https://github.com/hashicorp/boundary/pull/2495))

### Deprecations/Changes

* In 0.5.0, the `add-host-sets`, `remove-host-sets`, and `set-host-sets` actions
  on targets were deprecated in favor of `add-host-sources`,
  `remove-host-sources`, and `set-host-sources`. Originally these actions and
  API calls were to be removed in 0.6, but this was delayed to give extra time
  for clients to switch over. This has now been fully switched over. A database
  migration will modify any grants in roles to have the new actions. This same
  changeover has been made for `add-/remove-/set-credential-libraries` to
  `add-/remove-/set-credential-sources`, although those actions would only be in
  grant strings in very rare circumstances as the `-sources` actions replaced
  the `-libraries` actions very quickly.
  ([PR](https://github.com/hashicorp/boundary/pull/2393))

## 0.10.5 (2022/09/13)

### Known Issues

* There is bug that prevents deleting an org in some circumstances. This can be
  worked around by first deleting all projects in the org, then deleting the
  org. This will be fixed in 0.11.0.

### Bug Fixes

* grants: Properly resolve "only self" for permissions. When generating
  permissions from grants, if a single grant was limited only to a set of "self"
  actions and that was the last grant parsed (which would be semi-random
  depending on a number of factors), the overall set of permissions would be
  marked as only-self. This would result in the generated permissions being more
  limiting then they should be based on the grants. This only impacts the
  sessions list endpoint. It would result in users that have been granted access
  to list other user's sessions to be unable to see these sessions in the list
  results ([PR](https://github.com/hashicorp/boundary/pull/2448)).

## 0.10.4 (2022/09/13)

### Known Issues

* There is bug that prevents deleting an org in some circumstances. This can be
  worked around by first deleting all projects in the org, then deleting the
  org. This will be fixed in 0.11.0.

### New and Improved

* Controller-led worker authorization: This is a second authorization option for
  the workers using PKI-based authentication that was introduced in Boundary
  0.10.0. In 0.10.0, the only mode available was "worker-led", in which a worker
  generates an authorization request which can be submitted to a controller to
  authorize the worker. With this new controller-led flow, a worker can be
  created via the controller API first and return a one-time-use authorization
  token. This token can then be made available to the worker at startup time via
  its configuration file, env var, or a file with the value. If the worker is
  not authorized and this token is provided, it will use the token to authorize
  itself to the controller and set up PKI-based authentication.
  ([PR](https://github.com/hashicorp/boundary/pull/2413))
* Initial upstreams reloading on `SIGHUP`: Workers will now re-read the
  `initial_upstreams` value from the configuration file when given a SIGHUP.
  This allows a worker to reconnect to controllers if the full set of
  controllers has been changed over at the same time, without having to restart
  the worker. ([PR](https://github.com/hashicorp/boundary/pull/2417))
* Database URL reloading on `SIGHUP`: Controllers will now re-read the database
    url value from the configuration file when given a SIGHUP. This is
    particularly useful for allowing database credentials to rotate and
    signaling the controller to use the new credentials without the need for a
    restart. ([PR](https://github.com/hashicorp/boundary/pull/2422))
* Additional improvements to response time for listing sessions and targets
    ([PR](https://github.com/hashicorp/boundary/pull/2342)).

### Bug Fixes

* aws host catalog: Fix an issue where the request to list hosts could timeout
  on a large number of hosts
  ([Issue](https://github.com/hashicorp/boundary/issues/2224),
  [PR](https://github.com/hashicorp/boundary-plugin-host-aws/pull/17))
* aws host catalog: Fix an issue where filters could become unreadable in the UI
  if only one filter was created and was set by the CLI or directly via the API
  ([PR1](https://github.com/hashicorp/boundary/pull/2376),
  [PR2](https://github.com/hashicorp/boundary-plugin-host-aws/pull/16))
* aws host catalog: Use provided region for IAM calls in addition to EC2
  ([Issue](https://github.com/hashicorp/boundary/issues/2233),
  [PR](https://github.com/hashicorp/boundary-plugin-host-aws/pull/18))
* azure host catalog: Fix hosts not being found depending on the exact filter
  used because different filters return values with different casing
  ([PR](https://github.com/hashicorp/boundary-plugin-host-azure/pull/8))
* sessions: Fix an issue where sessions could not have more than one connection
  ([Issue](https://github.com/hashicorp/boundary/issues/2362),
  [PR](https://github.com/hashicorp/boundary/pull/2369))
* workers: Fix repeating error in logs when connected to HCP Boundary about an
  unimplemented HcpbWorkers call
  ([PR](https://github.com/hashicorp/boundary/pull/2361))
* workers: Fix a panic that could occur when `workers:create:worker-led` (e.g.
  via `boundary workers create worker-led`) was given an invalid token
  ([PR](https://github.com/hashicorp/boundary/pull/2388))
* workers: Add the ability to set API-based worker tags via the CLI
  ([PR](https://github.com/hashicorp/boundary/pull/2266))
* vault: Correctly handle Vault credential stores and libraries that are linked
  to an expired Vault token
  ([Issue](https://github.com/hashicorp/boundary/issues/2179),
  [PR](https://github.com/hashicorp/boundary/pull/2399))

## 0.10.3 (2022/08/30)

### Known Issues

* There is bug that prevents deleting an org in some circumstances. This can be
  worked around by first deleting all projects in the org, then deleting the
  org. This will be fixed in 0.11.0.

### Bug Fixes

* db: Fix an issue with migrations failing due to not updating the project_id
  value for the host plugin set
  ([Issue](https://github.com/hashicorp/boundary/issues/2349#issuecomment-1229953874),
  [PR](https://github.com/hashicorp/boundary/pull/2407)).

## 0.10.2 (2022/08/23)

### Known Issues

* There is bug that prevents deleting an org in some circumstances. This can be
  worked around by first deleting all projects in the org, then deleting the
  org. This will be fixed in 0.11.0.

### Security

* Fix security vulnerability CVE-2022-36130: Boundary up to 0.10.1 did not
  properly perform data integrity checks to ensure that host-set and
  credential-source resources being added to a target were associated with the
  same scope as the target. This could allow privilege escalation via allowing a
  user able to modify a target to provide connections to unintended hosts.
  [[HCSEC-2022-17](https://discuss.hashicorp.com/t/hcsec-2022017-boundary-allowed-access-to-host-sets-and-credential-sources-for-authorized-users-of-another-scope/43493)]

## 0.10.1 (2022/08/11)

### Bug Fixes

* db: Fix an issue with migrations affecting clusters that contain credential
  libraries or static credentials.
  ([Issue](https://github.com/hashicorp/boundary/issues/2349)),
  ([PR](https://github.com/hashicorp/boundary/pull/2351)).
* managed groups: Fix an issue where the `filter` field is not sent by admin UI
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1238)).
* host sets: Fix an issue causing host sets to not display in UI when using the
  aws plugin ([PR](https://github.com/hashicorp/boundary-ui/pull/1251))
* plugins: Fixes regression from 0.9.0 causing a failure to start when using
  multiple KMS blocks of the same type
  ([PR1](https://github.com/hashicorp/go-secure-stdlib/pull/43),
  [PR2](https://github.com/hashicorp/boundary/pull/2346))
* cli: Fixed errors related to URL detection when passing in `-attr` or
  `-secret` values that contained colons
  ([PR](https://github.com/hashicorp/boundary/pull/2353))

## 0.10.0 (2022/08/10)

### Known Issues

* Migration to this version may fail if the cluster contains credential
  libraries. This will be fixed shortly in 0.10.1.

### New and Improved

* `ssh` Target Type With Credential Injection (HCP Boundary only): Boundary has
  gained a new `ssh` target type. Using this type, username/password or SSH
  private key credentials can be sourced from `vault` credential libraries or
  `static` credentials and injected into the SSH session between a client and
  end host. This allows users to securely SSH to remote hosts while never being
  in possession of a valid credential for that target host.
* SSH Private Key Credentials: There is now an `ssh_private_key` credential type
  that allows submitting a username/private key (and optional passphrase) to
  Boundary for use with credential injection or brokering workflows.
* `boundary connect ssh` Credential Brokering Enhancements: we have extended
  support into the `boundary connect ssh` helper for brokered credentials of
  `ssh_private_key` type; the command will automatically pass the credentials to
  the `ssh` process ([PR](https://github.com/hashicorp/boundary/pull/2267)).
* `boundary authenticate`, `boundary accounts`: Enables use of `env://` and
  `file://` syntax to specify location of a password
  ([PR](https://github.com/hashicorp/boundary/pull/2325))

### Bug Fixes

* cli: Correctly cleanup plugins after exiting `boundary dev`, `boundary server`
  and `boundary database init`
  ([Issue](https://github.com/hashicorp/boundary/issues/2332),
  [PR](https://github.com/hashicorp/boundary/pull/2333)).
* `boundary accounts change-password`: Fixed being prompted for confirmation of
  the current password instead of the new one
  ([PR](https://github.com/hashicorp/boundary/pull/2325))

### Deprecations/Changes

* API Module: Changed the return types that reference interfaces into their
  expected typed definition. Type casting is only allowed against interface
  types, therefore to mitigate compiler errors please remove any type casting
  done against the return values.
  ([Issue](https://github.com/hashicorp/boundary/issues/2122),
  [PR](https://github.com/hashicorp/boundary/pull/2238))
* Targets: Rename Application credentials to Brokered credentials
  ([PR](https://github.com/hashicorp/boundary/pull/2260)).
* Host plugins: Plugin-type host catalogs/sets/hosts now use typed prefixes for
  any newly-created resources. Existing resources will not be affected.
  ([PR](https://github.com/hashicorp/boundary/pull/2256))
* Credential stores: Static-type credential stores/credentials now use typed
  prefixes for any newly-created resources. Existing resources will not be
  affected. ([PR](https://github.com/hashicorp/boundary/pull/2256))
* Change of behavior on `-token` flag in CLI: Passing a token this way can
  reveal the token to any user or service that can look at process information.
  This flag must now reference a file on disk or an env var. Direct usage of the
  `BOUNDARY_TOKEN` env var is also deprecated as it can show up in environment
  information; the `env://` format now supported by the `-token` flag causes the
  Boundary process to read it instead of the shell so is safer.
  ([PR](https://github.com/hashicorp/boundary/pull/2327))
* Change of behavior on `-password` flag in CLI: The same change made above for
  `-token` has also been applied to `-password` or, for supporting resource
  types, `-current-password` and `-new-password`.
  ([PR](https://github.com/hashicorp/boundary/pull/2327))

## 0.9.1 (2022/07/06)

### New and Improved

* `azure` host plugin: Support multiple MSI identities
  ([PR](https://github.com/hashicorp/go-kms-wrapping/pull/97))

### Bug Fixes

* scheduler: Fix regression causing controller names of less than 10 characters
  to fail to register jobs
  ([PR](https://github.com/hashicorp/boundary/pull/2226)).
* sessions: Fix an additional case from the changes in the 0.8.x series that
  could result in sessions never moving from `canceling` state to terminated.
  ([PR](https://github.com/hashicorp/boundary/pull/2229))
* The plugin execution_dir configuration parameter is now respected by kms plugins too
  ([PR](https://github.com/hashicorp/boundary/pull/2239)).

### Deprecations/Changes

* sessions: The default connect limit for new sessions changed from 1 to unlimited (-1).
  Specific connection limits is an advanced feature of Boundary and this setting is
  more friendly for new users.
  ([PR](https://github.com/hashicorp/boundary/pull/2234))

## 0.9.0 (2022/06/20)

### Known Issues

* If a controller's defined name in a configuration file is less than 10
  characters, errors may be seen on startup related to registration of jobs.
  This is a regression in this version and will be fixed in the next release.

### New and Improved

* PKI Workers: This release introduces a new worker type `pki` which
  authenticates to Boundary using a new certificate-based method, allowing for
  worker deployment without using a shared KMS.
* Credentials: This release introduces a new credential store type `static`,
  which simply takes in a user-supplied credential and stores it (encrypted)
  directly in Boundary. Currently, the `static` credential store can hold
  credentials of type `username_password`. These credentials can act as
  credential sources for targets, similar to credential libraries from the
  `vault` credential store, and thus can be brokered to users at session
  authorization time. ([PR](https://github.com/hashicorp/boundary/pull/2174))
* `boundary connect` Credential Brokering Integration: we have extended integration
  into the `boundary connect` helpers. A new `sshpass` style has been added to the
  `ssh` helper, when used, if the credential contains a username/password and `sshpass`
  is installed, the command will automatically pass the credentials to the `ssh` process.
  Additionally, the default `ssh` helper will now use the `username` of the brokered credential.
  ([PR](https://github.com/hashicorp/boundary/pull/2191)).
* controller: Improve response time for listing sessions.
  This also creates a new periodic job that will delete terminated
  sessions after 1 hour.
  See Deprecations/Changes for some additional details.
  ([PR](https://github.com/hashicorp/boundary/pull/2160)).
* event filtering: Change event filters to use lowercase and snake case for data
  elements like the rest of Boundary filters do.
* ui: Use include_terminated flag for listing sessions.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1126)).
* ui: Add Quick Setup onboarding guide.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1140)).

### Bug Fixes

* The plugin execution_dir configuration parameter is now respected.
  ([PR](https://github.com/hashicorp/boundary/pull/2183)).
* ui: Fix Users page not updating fields correctly.
  ([PR](https://github.com/hashicorp/boundary-ui/pull/1105)).

### Deprecations/Changes

* Targets: Removes support for `credential libraries` with respect to Target resources.
  The `library` `fields` and `actions` were deprecated in [Boundary 0.5.0](#050-20210802),
  please use `credential sources` instead. See changelog referenced above for
  more details ([PR](https://github.com/hashicorp/boundary/pull/1533)).
* Credential Libraries: The `user_password` credential type has been renamed to
  `username_password` to remove any inconsistency over what the credential type is.
  All existing `user_password` typed credential libraries will be migrated to
  `username_password` ([PR](https://github.com/hashicorp/boundary/pull/2154)).
* controller: Change the default behavior of the session list endpoint
  to no longer include sessions in a terminated state and introduces
  a new query parameter/cli flag to include the terminated sessions.
  This also removes the connection information from the list response.
  ([PR](https://github.com/hashicorp/boundary/pull/2160)).
* Anonymous user permissions: In order to reduce the risk of accidental and
  unintended granting of permissions to anonymous users, the permissions system
  now only allows certain actions on certain resources to be assigned to the
  anonymous user; currently these are the same permissions as assigned in
  Boundary's default role permissions. If other use-cases arise this list can be
  expanded. See [the
  documentation](https://www.developer.hashicorp.com/boundary/docs/rbac/assignable-permissions)
  for more details.

## 0.8.1 (2022/05/13)

### Bug Fixes

* controller: Do not shut down cluster listener when it receives an invalid
  packet ([Issue](https://github.com/hashicorp/boundary/issues/2072),
  [PR](https://github.com/hashicorp/boundary/pull/2073))
* session: update cancel_session() function to check for terminated state
  ([Issue](https://github.com/hashicorp/boundary/issues/2064),
  [PR](https://github.com/hashicorp/boundary/pull/2065))

## 0.8.0 (2022/05/03)

### New and Improved
* metrics: Provide metrics for controllers and workers
* controller: Add health endpoint ([PR](https://github.com/hashicorp/boundary/pull/1882))
* controller: Improve response time for listing sessions and targets.
  ([PR](https://github.com/hashicorp/boundary/pull/2049))
* ui: Add support for worker filters in targets
* ui: Add manual refresh button in sessions list
* Audit events are no longer a WIP ([PR](https://github.com/hashicorp/boundary/pull/2031)).

### Bug Fixes

* worker: create new error to prevent `event.newError: missing error: invalid
  parameter` and handle session cancel with no TOFU token
  ([Issue](https://github.com/hashicorp/boundary/issues/1902),
  [PR](https://github.com/hashicorp/boundary/pull/1929))
* controller: Reconcile DEKs with existing scopes
  ([Issue](https://github.com/hashicorp/boundary/issues/1856),
  [PR](https://github.com/hashicorp/boundary/pull/1976))
* controller: Fix for retrieving sessions that could result in incomplete
  results when there is a large number (10k+) of sessions.
  ([PR](https://github.com/hashicorp/boundary/pull/2049))
* session: update session state trigger to prevent transitions to invalid states
  ([Issue](https://github.com/hashicorp/boundary/issues/2040),
  [PR](https://github.com/hashicorp/boundary/pull/2046))

## 0.7.6 (2022/03/15)

### Bug Fixes

* sessions: Sessions and session connections have been refactored to better
isolate transactions and prevent resource contention that caused deadlocks.
([Issue](https://github.com/hashicorp/boundary/issues/1812),
  [PR](https://github.com/hashicorp/boundary/pull/1919))
* scheduler: Fix bug that causes erroneous logs when racing controllers
  attempted to run jobs
  ([Issue](https://github.com/hashicorp/boundary/issues/1903),
  [PR](https://github.com/hashicorp/boundary/pull/1914)).

## 0.7.5 (2022/02/17)

### New and Improved

* cli: Update authentication examples to remove password flag and make
  subcommend selection a bit clearer
  ([PR](https://github.com/hashicorp/boundary/pull/1835))
* Data Warehouse: Add addresses on plugin based hosts to the database warehouse.
  3 new dimension tables have been added including `wh_network_address_group`
  (which is now referenced by `wh_host_dimension`),
  `wh_network_address_dimension`, and `wh_network_address_group_membership`.
  ([PR](https://github.com/hashicorp/boundary/pull/1855))
* ui: Add support for dynamic host catalog. AWS and Azure plugin-based CRUD operations.

### Bug Fixes

* targets: Specifying a plugin based host id when authorizing a session
  now works. ([PR](https://github.com/hashicorp/boundary/pull/1853))
* targets: DNS names are now properly parsed when selecting an endpoint
  for authorizing a session.
  ([PR](https://github.com/hashicorp/boundary/pull/1849))
* hosts: Static hosts now include the host sets they are in.
  ([PR](https://github.com/hashicorp/boundary/pull/1828))

## 0.7.4 (2022/01/18)

### Deprecations/Changes

* In newly-created scopes, if default role creation is not disabled, the roles
  will now contain a grant to allow listing targets. This will still be subject
  to listing visibility rules, so only targets the user is granted some action
  on (such as `authorize-session`) will be returned.

### New and Improved

* config: The `description` field for workers now supports being set
  from environment variables or a file on disk
  ([PR](https://github.com/hashicorp/boundary/pull/1783))
* config: The `max_open_connections` field for the database field in controllers now supports being set
  from environment variables or a file on disk
  ([PR](https://github.com/hashicorp/boundary/pull/1776))
* config: The `execution_dir` field for plugins now supports being set from environment variables
  or a file on disk.([PR](https://github.com/hashicorp/boundary/pull/1772))
* config: Add support for reading worker controllers off of environment
  variables as well as files. ([PR](https://github.com/hashicorp/boundary/pull/1765))
* config: The `description` field for controllers now supports being set
  from environment variables or a file on disk
  ([PR](https://github.com/hashicorp/boundary/pull/1766))
* config: Add support for reading worker tags off of environment variables
  as well as files. ([PR](https://github.com/hashicorp/boundary/pull/1758))
* config: Add support for go-sockaddr templates to Worker and Controller
  addresses. ([PR](https://github.com/hashicorp/boundary/pull/1731))
* controllers/workers: Add client IP to inbound request information which is included in
  Boundary events ([PR](https://github.com/hashicorp/boundary/pull/1678))
* host: Plugin-based host catalogs will now schedule updates for all
  of its host sets when its attributes are updated.
  ([PR](https://github.com/hashicorp/boundary/pull/1736))
* scopes: Default roles in newly-created scopes now contain a grant to allow
  listing targets. ([PR](https://github.com/hashicorp/boundary/pull/1803))
* plugins/aws: AWS plugin based hosts now include DNS names in addition to the
  IP addresses they already provide.

### Bug Fixes
* session: Fix duplicate sessions and invalid session state transitions. ([PR](https://github.com/hashicorp/boundary/pull/1793))

## 0.7.3 (2021/12/16)

### Bug Fixes

* target: Fix permission bug which prevents the UI from being able to add and remove
  host sources on a target. ([PR](https://github.com/hashicorp/boundary/pull/1794))
* credential: Fix panic during credential issue when a nil secret is received. This can
  occur when using the Vault KV backend which returns a nil secret and no error if the
  secret does not exist. ([PR](https://github.com/hashicorp/boundary/pull/1798))

## 0.7.2 (2021/12/14)

### Security

* Boundary now uses Go 1.17.5 to address a security vulnerability (CVE-2021-44716) where
  an attacker can cause unbounded memory growth in a Go server accepting HTTP/2 requests.
  See the [Go announcement](https://groups.google.com/g/golang-announce/c/hcmEScgc00k) for
  more details. ([PR](https://github.com/hashicorp/boundary/pull/1789))

## 0.7.1 (2021/11/18)

### Bug Fixes

* db: Fix panic invoking the CLI on Windows. Some changes to how the binary is
  initialized resulted in running some functions on every startup that looked
  for some embedded files. However, Go's embed package does not use OS-specific
  path separators, so a mismatch between path separators caused a failure in the
  function. ([PR](https://github.com/hashicorp/boundary/pull/1733))

## 0.7.0 (2021/11/17)

### Deprecations/Changes

* tls: Boundary's support for TLS 1.0/1.1 on the API listener was broken. Rather
  than fix this, we are simply not supporting TLS 1.0/1.1 as they are insecure.

### New and Improved

* Boundary now supports dynamic discovery of host resources using our (currently
  internal) new plugin system. See the
  [documentation](https://www.developer.hashicorp.com/boundary/docs) for configuration
  instructions. Currently, only Azure and AWS are supported, but more providers
  will be following in future releases.
* workers: The existing worker connection replay prevention logic has been
  enhanced to be more robust against attackers that have decryption access to
  the shared `worker-auth` KMS key
  ([PR](https://github.com/hashicorp/boundary/pull/1641))

### Bug Fixes

* tls: Support TLS 1.2 for more clients. This was broken for some clients due to
  a missing mandated cipher suite of the HTTP/2 (`h2`) specification that could
  result in no shared cipher suites between the Boundary API listener and those
  clients. ([PR](https://github.com/hashicorp/boundary/pull/1637))
* vault: Fix credential store support when using Vault namespaces
  ([Issue](https://github.com/hashicorp/boundary/issues/1597),
  [PR](https://github.com/hashicorp/boundary/pull/1660))

## 0.6.2 (2021/09/27)

### Deprecations/Changes

* permissions: Fix bug in _Host Sets_ service that authenticated requests
  againist incorrect grant actions. This bug affects the _SetHosts_, _AddHosts_
  and _RemoveHosts_ paths that do not have wildcard (`*`) action grants.
  If affected, please update grant actions as follows:
* * `set-host-sets` -> `set-hosts`
* * `add-host-sets` -> `add-hosts`
* * `remove-host-sets` -> `remove-hosts`
  ([PR](https://github.com/hashicorp/boundary/pull/1549)).
* Removes support for the `auth-methods/<id>:authenticate:login` action that was
  deprecated in [Boundary 0.2.0](#020-20210414), please use
  `auth-methods/<id>:authenticate` instead.
  ([PR](https://github.com/hashicorp/boundary/pull/1534)).
* Removes support for the `credential` field within `auth-methods/<id>:authenticate`
  action. This field was deprecated in [Boundary 0.2.0](#020-20210414), please use
  `attributes` instead.
  ([PR](https://github.com/hashicorp/boundary/pull/1534)).

## 0.6.1 (2021/09/14)

### Bug Fixes

* grants: Fix issue where `credential-store`, `credential-library`, and
  `managed-group` would not be accepted as specific `type` values in grant
  strings. Also, fix authorized actions not showing `credential-store` values in
  project scope output. ([PR](https://github.com/hashicorp/boundary/pull/1524))
* actions: Fix `sessions` collection actions not being visible when reading a
  scope ([PR](https://github.com/hashicorp/boundary/pull/1527))
* credential stores: Fix credential stores not showing authorized collection
  actions ([PR](https://github.com/hashicorp/boundary/pull/1530))

## 0.6.0 (2021/09/03)

### New and Improved

* ui: Reflect user authorized actions in the UI:  users now see only actionable
  items for which they have permissions granted.
* ui: Icons refreshed for a friendlier look and feel.

### Bug Fixes

* controller: Fix issue with recursive listing across services when using the
  unauthenticated user (`u_anon`) with no token and the list was started in a
  scope where the user does not have permission
  ([PR](https://github.com/hashicorp/boundary/pull/1478))
* grants: Fix grant format `type=<type>;output_fields=<fields>` with no action
  specified. In some code paths this format would trigger an error when
  validating even though it is correctly handled within the ACL code.
  ([PR](https://github.com/hashicorp/boundary/pull/1474))
* targets: Fix panic when using `boundary targets authorize-session`
  ([Issue](https://github.com/hashicorp/boundary/issues/1488),
  [PR](https://github.com/hashicorp/boundary/pull/1496))

## 0.5.1 (2021/08/16)

### New and Improved

* Data Warehouse: Add OIDC auth method and accounts to the database warehouse.
  Four new columns have been added to the `wh_user_dimension` table:
  `auth_method_external_id`, `auth_account_external_id`,
  `auth_account_full_name`, and `auth_account_email`.
  ([PR](https://github.com/hashicorp/boundary/pull/1455))

### Bug Fixes

* events: Fix panic when using the `hclog-text` event's format.
  ([PR](https://github.com/hashicorp/boundary/pull/1456))
* oidc managed groups: Allow colons in selector paths
  ([PR](https://github.com/hashicorp/boundary/pull/1453))

## 0.5.0 (2021/08/02)

### Deprecations/Changes

* With respect to Target resources, two naming changes are taking place. Note
  that these are not affecting the resources themselves, only the fields on
  Target resources that map them to targets:
* * _Credential Libraries_: In Target definitions, the field referring to
    attached credential libraries is being renamed to the more abstract
    _credential sources_. In the future Boundary will gain the ability to
    internally store static credentials that are not generated or fetched
    dynamically, and the _sources_ terminology better reflects that the IDs
    provided are a source of credentials, whether via dynamic generation or via
    the credentials themselves. This will allow a paradigm similar to
    `principals` with roles, where the principal IDs can be a users, groups, and
    managed groups, rather than having them split out, and should result in an
    easier user experience once those features roll out compared to having
    separate flags and fields. In this 0.5 release the Boundary CLI has gained
    parallel `application-credential-source` flags to the existing
    `application-credential-library` flags, as well as `boundary targets
    add/remove/set-credential-sources` commands that parallel `boundary targets
    add/remove/set-credential-libraries` commands. This parallelism extends to
    the API actions and the grants system. In 0.6, the _library_ versions of
    these commands, flags, and actions will be removed.
* * _Host Sets_: Similarly, in Target definitions, the field referring to
    attached host sets is being renamed to the more abstract _host sources_. In
    the future Boundary will allow attaching some host types directly, and
    possibly other mechanisms for gathering hosts for targets, so the _sources_
    terminology better reflects that the IDs provided are a source of hosts,
    whether via sets or via the hosts themselves. Like with credential sources,
    in this 0.5 release the Boundary CLI and API have gained parallel API
    actions and fields, and the _set_ versions of these will be removed in 0.6.

### New and Improved

* OIDC Accounts: When performing a `read` on an `oidc` type account, the
  original token and userinfo claims are provided in the output. This can make
  it significantly easier to write filters to create [managed
  groups](https://www.developer.hashicorp.com/boundary/docs/rbac/users/managed-groups).
  ([PR](https://github.com/hashicorp/boundary/pull/1419))
* Controllers will now mark connections as closed in the database if the worker
  has not reported its status; this can be seen as the controller counterpart to
  the worker-side session cleanup functionality released in 0.4.0. As with the
  worker, the timeout for this behavior is 15s.
* Workers will shut down connections gracefully upon shutdown of the worker,
  both closing the connection and sending a request to mark the connection as
  closed in the database.
* Pressing CTRL-C (or sending a SIGINT) when Boundary is already shutting
  down due to a CTRL-C or interrupt will now cause Boundary to immediately shut
  down non-gracefully. This may leave various parts of the Boundary deployment
  (namely sessions or connections) in an inconsistent state.

* Events: Boundary has moved from writing hclog entries to emitting events.
  There are four types of Boundary events: `error`, `system`, `observation` and
  `audit`. All events are emitted as
  [cloudevents](https://github.com/cloudevents/spec/blob/v1.0.1/spec.md) and we
  support both a `cloudevents-json` format and custom Boundary
  `cloudevents-text` format.

  **Notes**:
  * There are still a few lingering hclog bits within Boundary. If you wish to
    only output json from Boundary logging/events then you should specify both
    `"-log-format json"` and `"-event-format cloudevents-json"` when starting
    Boundary.
  * Filtering events: hclog log levels have been replaced by optional sets
    of allow and deny event
    [filters](https://www.developer.hashicorp.com/boundary/docs/filtering) which are
    specified via configuration, or in the case of "boundary dev" there are new
    new cmd flags.
  * Observation events are MVP and contain a minimal set of observations about a
    request. Observations are aggregated for each request, so only one
    observation event will be emitted per request. We anticipate that a rich set
    of aggregate data about each request will be developed over time.
  * Audit events are a WIP and will only be emitted if they are both enabled
    and the env var `BOUNDARY_DEVELOPER_ENABLE_EVENTS` equals true.  We
    anticipate many changes for audit events before they are generally available
    including what data is included and different options for
    redacting/encrypting that data.


  PRs:
    [hclog json,text formats](https://github.com/hashicorp/boundary/pull/1440),
    [log adapters](https://github.com/hashicorp/boundary/pull/1434),
    [unneeded log deps](https://github.com/hashicorp/boundary/pull/1433),
    [update eventlogger](https://github.com/hashicorp/boundary/pull/1411),
    [convert from hclog to events](https://github.com/hashicorp/boundary/pull/1409),
    [event filtering](https://github.com/hashicorp/boundary/pull/1404),
    [cloudevents node](https://github.com/hashicorp/boundary/pull/1390),
    [system events](https://github.com/hashicorp/boundary/pull/1360),
    [convert errors to events](https://github.com/hashicorp/boundary/pull/1358),
    [integrate events into servers](https://github.com/hashicorp/boundary/pull/1355),
    [event pkg name](https://github.com/hashicorp/boundary/pull/1284),
    [events using ctx](https://github.com/hashicorp/boundary/pull/1277),
    [add eventer](https://github.com/hashicorp/boundary/pull/1276),
    [and base event types](https://github.com/hashicorp/boundary/pull/1275)
### Bug Fixes

* config: Fix error when populating all `kms` purposes in separate blocks (as
  well as the error message)
  ([Issue](https://github.com/hashicorp/boundary/issues/1305),
  [PR](https://github.com/hashicorp/boundary/pull/1384))
* server: Fix panic on worker startup failure when the server was not also
  configured as a controller
  ([PR](https://github.com/hashicorp/boundary/pull/1432))

### New and Improved

* docker: Add support for muti-arch docker images (amd64/arm64) via Docker buildx

## 0.4.0 (2021/06/29)

### New and Improved

* Credential Stores: This release introduces Credential Stores, with the first
  implementation targeting Vault. A credential store can be created that accepts
  a Vault periodic token (which it will keep refreshed) and connection
  information allowing it to make requests to Vault.
* Credential Libraries: This release introduces Credential Libraries, with the
  first implementation targeting Vault. Credential libraries describe how to
  make a request to fetch a credential from the credential store. The first
  credential library is the `generic` type that takes in a user-defined request
  body to send to Vault and thus can work for any type of Vault secrets engine.
  When a credential library is used to fetch a credential, if the credential
  contains a lease, Boundary will keep the credential refreshed, and revoke the
  credential when the session that requested it is finished.
* Credential Brokering: Credential libraries can be attached to targets; when a
  session is authorized against that target, a credential will be fetched from
  the library that is then relayed to the client. The client can then use this
  information to make a connection, allowing them to gain the benefit of dynamic
  credential generation from Vault, but without needing their own Vault
  login/token (see NOTE below).
* `boundary connect` Credential Brokering Integration: Additionally, we have
  started integration into the `boundary connect` helpers, starting in this
  release with the Postgres helper; if the credential contains a
  username/password and `boundary connect postgres` is the helper being used,
  the command will automatically pass the credentials to the `psql` process.
* The worker will now close any existing proxy connections it is handling when
  it cannot make a status request to the controller. The timeout for this
  behavior is currently 15 seconds.

NOTE: When using credential brokering, remember that if the user can connect
directly to the end resource, they can use the brokered username and password
via that direct connection to skip Boundary. This isn't any different from
normal Boundary behavior (if a user can directly connect, they can bypass
Boundary) but it's worth repeating.

### Bug Fixes

* scheduler: removes a Postgres check constraint, on the length of the controller name,
  causing an error when the scheduler attempts to run jobs
  ([Issue](https://github.com/hashicorp/boundary/issues/1309),
  [PR](https://github.com/hashicorp/boundary/pull/1310)).
* Docker: update entrypoint script to handle more Boundary subcommands for
  better UX

## 0.3.0 (2021/06/08)

### Deprecations/Changes

* `password` account IDs: When the `oidc` auth method came out, accounts were
  given the prefix `acctoidc`. Unfortunately, accounts in the `password` method
  were using `apw`...oops. We're standardizing on `acct` and have updated the
  `password` method to generate new IDs with `acctpw` prefixes.
  Previously-generated prefixes will continue to work.

### New and Improved

* oidc: The new Managed Groups feature allows groups of accounts to be created
  based on an authenticating user's JWT or User Info data. This data uses the
  same filtering syntax found elsewhere in Boundary to provide a rich way to
  specify the criteria for group membership. Once defined, authenticated users
  are added to or removed from these groups as appropriateds each time they
  authenticate. These groups are treated like other role principals and can be
  added to roles to provide grants to users.
* dev: Predictable IDs in `boundary dev` mode now extend to the accounts created
  in the default `password` and `oidc` auth methods.
* mlock: Add a Docker entrypoint script and modify Dockerfiles to handle mlock
  in a fashion similar to Vault
  ([PR](https://github.com/hashicorp/boundary/pull/1269))

## 0.2.3 (2021/05/21)

### Deprecations/Changes

* The behavior when `cors_enabled` is not specified for a listener is changing
  to be equivalent to a `cors_allowed_origins` value of `*`; that is, accept all
  origins. This allows Boundary, by default, to have the admin UI and desktop
  client work without further specification of origins by the operator. This is
  only affecting default behavior; if `cors_enabled` is explicitly set to
  `true`, the behavior will be the same as before. This had been changed in
  v0.2.1 due to a bug found in v0.2.0 that caused all origins to always be
  allowed, but fixing that bug exposed that the default behavior was difficult
  for users to configure to simply get up and running.
* If a `cancel` operation is run on a session already in a canceling or
  terminated state, a `200` and the session information will be returned instead
  of an error.

### New and Improved

* sessions: Return a `200` and session information when canceling an
  already-canceled or terminated session
  ([PR](https://github.com/hashicorp/boundary/pull/1243))

### Bug Fixes

* cors: Change the default allowed origins when `cors_enabled` is not specified
  to be `*`. ([PR](https://github.com/hashicorp/boundary/pull/1249))

## 0.2.2 (2021/05/17)

### New and Improved

* Inline OIDC authentication flow:  when the OIDC authentication flow succeeds,
  the third-party provider browser window is automatically closed and the user
  is returned to the admin UI.

### Bug Fixes

* oidc: If provider returns an `aud` claim as a `string` or `[]string`,
  Boundary will properly parse the claims JSON.
  ([Issue](https://github.com/hashicorp/cap/issues/37),
  [PR](https://github.com/hashicorp/boundary/pull/1231))
* sessions: Clean up connections that are dangling after a worker dies (is
  restarted, powered off, etc.) This fixes some cases where a session never goes
  to `terminated` state because connections are not properly marked closed.
  ([Issue 1](https://github.com/hashicorp/boundary/issues/894), [Issue
  2](https://github.com/hashicorp/boundary/issues/1055),
  [PR](https://github.com/hashicorp/boundary/pull/1220))
* sessions: Add some missing API-level checks when session cancellation was
  requested. It's much easier than interpreting the domain-level check failures.
  ([PR](https://github.com/hashicorp/boundary/pull/1223))
* authenticate: When authenticating with OIDC and `json` format output, the
  command will no longer print out a notice that it's opening your web browser
  ([Issue](https://github.com/hashicorp/boundary/issues/1193),
  [PR](https://github.com/hashicorp/boundary/pull/1213))

## 0.2.1 (2021/05/05)

### Deprecations/Changes

* API `delete` actions now result in a `204` status code and no body when
  successful. This was not the case previously due to a technical limitation
  which has now been solved.
* When using a `delete` command within the CLI we now either show success or
  treat the `404` error the same as any other `404` error, that is, it results
  in a non-zero status code and an error message. This makes `delete` actions
  behave the same as other commands, all of which pass through errors to the
  CLI. Given `-format json` capability, it's relatively easy to perform a check
  to see whether an error was `404` or something else from within scripts, in
  conjunction with checking that the returned status code matches the API error
  status code (`1`).
* When outputting from the CLI in JSON format, the resource information under
  `item` or `items` (depending on the action) now exactly matches the JSON sent
  across the wire by the controller, as opposed to matching the Go SDK
  representation which could result in some extra fields being shown or fields
  having Go-specific types. This includes `delete` actions which previously
  would show an object indicating existence, but now show no `item` on success
  or the API's `404` error.
* Permissions in new scope default roles have been updated to include support
  for `list`, `read:self`, and `delete:self` on `auth-token` resources. This
  allows a user to list and manage their own authentication tokens. (As is the
  case with other resources, `list` will still be limited to returning tokens on
  which the user has authorization to perform actions, so granting this
  capability does not automatically give user the ability to list other users'
  authentication tokens.)

### New and Improved

* permissions: Improving upon the work put into 0.2.0 to limit the fields that
  are returned when listing as the anonymous user, grants now support a new
  `output_fields` section. This takes in a comma-delimited (or in JSON format,
  array) set of values that correspond to the JSON fields returned from an API
  call (for listing, this will be applied to each resource under the `items`
  field). If specified for a given ID or resource type (and scoped to specific
  actions, if included), only the given values will be returned in the output.
  If no `output_fields` are specified, the defaults are used. For authenticated
  users this defaults to all fields; for `u_anon` this defaults to the fields
  useful for navigating to and authenticating to the system. In either case,
  this is overridable. See the [permissions
  documentation](https://www.developer.hashicorp.com/boundary/docs/rbac)
  for more information on why and when to use this. This currently only applies
  to top-level fields in the response.
* cli/api/sdk: Add support to request additional OIDC claims scope values from
  the OIDC provider when making an authentication request.
  ([PR](https://github.com/hashicorp/boundary/pull/1175)).

  By default, Boundary only requests the "openid" claims scope value. Many
  providers, like Okta and Auth0 for example, will not return the standard claims
  of email and name when you request the default claims scope (openid).

  Boundary uses the standard email and name claims to populate an OIDC
  account's `Email` and `FullName` attributes. If you'd like these account
  attributes populated, you'll need to reference your OIDC provider's documentation
  to learn which claims scopes are required to have these claims returned during
  the authentication process.

  Boundary now provides a new OIDC auth method parameter `claims_scopes` which
  allows you to add multiple additional claims scope values to an OIDC auth
  method configuration.

  For information on claims scope values see: [Scope Claims in the OIDC
  specification](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)

* cli: Match JSON format output with the across-the-wire API JSON format
  ([PR](https://github.com/hashicorp/boundary/pull/1155))
* api: Return `204` instead of an empty object on successful `delete` operations
  ([PR](https://github.com/hashicorp/boundary/pull/1155))
* actions: The new `no-op` action allows a grant to be given to a principals
  without conveying any actionable result. Since resources do not appear in list
  results if the principal has no actions granted on that resource, this can be
  used to allow principals to see values in list results without also giving
  `read` or other capabilities on the resources. The default scope permissions
  have been updated to convey `no-op,list` instead of `read,list`.
  ([PR](https://github.com/hashicorp/boundary/pull/1138))
* cli/api/sdk: User resources have new attributes for:
  * Primary Account ID
  * Login Name
  * Full Name
  * Email

  These new user attributes correspond to attributes from the user's primary
  auth method account. These attributes will be empty when the user has no
  account in the primary auth method for their scope, or there is no designated
  primary auth method for their scope.
* cli: Support for reading and deleting the user's own token via the new
  `read:self` and `delete:self` actions on auth tokens. If no token ID is
  provided, the stored token's ID will be used (after prompting), or `"self"`
  can be set as the value of the `-id` parameter to trigger this behavior
  without prompting. ([PR](https://github.com/hashicorp/boundary/pull/1162))
* cli: New `logout` command deletes the current token in Boundary and forgets it
  from the local system credential store, respecting `-token-name`
  ([PR](https://github.com/hashicorp/boundary/pull/1134))
* config: The `name` field for workers and controllers now supports being set
  from environment variables or a file on disk
  ([PR](https://github.com/hashicorp/boundary/pull/1181))

### Bug Fixes

* cors: Fix allowing all origins by default
  ([PR](https://github.com/hashicorp/boundary/pull/1134))
* cli: It is now an error to run `boundary database migrate` on an uninitalized db.
  Use `boundary database init` instead.
  ([PR](https://github.com/hashicorp/boundary/pull/1184))
* cli: Correctly honor the `-format` flag when running `boundary database init`
  ([PR](https://github.com/hashicorp/boundary/pull/1204))

## 0.2.0 (2021/04/14)

### Known Issues

* By default, CORS support will allow all origins. This is due to a bug in how
  the set of allowed origins was processed, in conjunction with changes to CORS
  behavior to automatically include the origin of the Desktop Client. This will
  be fixed in 0.2.1. In the meantime, this can be worked around by either
  explicitly disabing CORS with `cors_enabled = false` in the `listener` config
  block with purpose `api`; or setting a `cors_allowed_origins` field to have
  values other than `serve://boundary` (including values that do not map to any
  real origin).

### Deprecations/Changes

* The `auth-methods/<id>:authenticate:login` action is deprecated and will be
  removed in a few releases. (Yes, this was meant to deprecate the
  `authenticate` action; apologies for going back on this!) To better support
  future auth methods, and especially the potential for plugins, rather than
  defining custom actions on the URL path the `authenticate` action will consume
  both a map of parameters but also a `command` parameter that specifies the
  type of command. This allows workflows that require multiple steps, such as
  OIDC, to not require custom subactions. Additionally, the `credentials` map in
  the `authenticate` action has been renamed `attributes` to better match other
  types of resources. `credentials` will still work for now but will be removed
  in a few releases. Finally, in the Go SDK, the `Authenticate` function now
  requires a `command` value to be passed in.
* Related to the above change, the output of an API
  `auth-methods/<id>:authenticate` call will return the given `command` value
  and a map of attributes that depend on the given command. On the SDK side, the
  output of the `Authenticate` function returns a map, from which a concrete
  type can be easily umarshaled (see the updated `authenticate password` command
  for an example).
* Anonymous scope/auth method listing: When listing auth methods and scopes
  without authentication (that is, as the anonymous user `u_anon`), only
  information necessary for navigation to an auth method and authenticating to
  the auth method is now output. Granting `u_anon` list access to other resource
  types will not currently filter any information out.

### New and Improved

* cli/api/sdk: New OIDC auth method type added with support for create, read,
  update, delete, and list (see new cli `oidc` subcommands available on CRUDL
  operations for examples), as well as the ability to authenticate against it
  via the SDK, CLI, admin UI, and desktop client.
  ([PR](https://github.com/hashicorp/boundary/pull/1090))
* server: When performing recursive listing, `list` action is no longer required
  to be granted to the calling user. Instead, the given scope acts as the root
  point (so only results under that scope will be shown), and `list` grant is
  evaluated per-scope. ([PR](https://github.com/hashicorp/boundary/pull/1016))
* database init: If the database is already initialized, return 0 as the exit
  code. This matches how the `database migrate` command works.
  ([PR](https://github.com/hashicorp/boundary/pull/1033))

### Bug Fixes

* server: Roles for auto generated scopes are now generated at database init.
  ([PR](https://github.com/hashicorp/boundary/pull/996))
* cli: Don't panic on certain commands when outputting in `json` format
  ([Issue](https://github.com/hashicorp/boundary/pull/992),
  [PR](https://github.com/hashicorp/boundary/pull/1095))

## 0.1.8 (2021/03/10)

### Known Issues

These are specific known issues in the release that we feel are impactful enough
to call out in this changelog. The full set of open issues is on GitHub.

* cli: When authenticating, changing a password, or a couple of other specific
  actions on the CLI, if the output format is specified as `json`, the command
  will panic (after the API call executes). This is due to a preexisting bug
  that was exposed by the JSON changes described in the changes section below.
  Although most of our CLI-level tests operate on `json`-format output, because
  our CLI-level tests use the token helper during execution, the authentication
  test was using the normal table output since the output was ignored anyways.
  As a result, our CLI tests did not catch this panic. Our apologies, and we
  will fix this in the next release.
* Initially Created Scopes: Starting in 0.1.6, When initial scopes are created
  when executing `boundary database init`, the associated admin roles aren't
  created. The intended behavior is to have a role which granted the auto
  created admin the grant `"id=*;type=*;actions=*"` for each auto generated
  scope.  To set your data to the intended state you can add a role for the
  admin user in the generated scopes.  An outline of the steps to do this can
  be found in this
  [gist](https://gist.github.com/talanknight/98492dc68d894f67742086eb41fdb506).
  This will be fixed in the next release.

### Changes/Deprecations

* sdk (Go API library): A few functions have changed places. Notably, instead of
  `ResponseMap()` and `ResponseBody()`, resources simply expose `Response()`.
  This higher-level response object contains the map and body, and also exposes
  `StatusCode()` in place of indivdidual resources.
  ([PR](https://github.com/hashicorp/boundary/pull/962))
* cli: In `json` output format, a resource item is now an object under the
  top-level key `item`; a list of resource items is now an list of objects under
  the top-level key `items`. This preserves the top level for putting in other
  useful information later on (and the HTTP status code is included now).
  ([PR](https://github.com/hashicorp/boundary/pull/962))
* cli: In `json` output format, errors are now serialized as a JSON object with
  an `error` key instead of outputting normal text
  ([PR](https://github.com/hashicorp/boundary/pull/962))
* cli: All errors, including API errors, are now written to `stderr`. Previously
  in the default table format, API errors would be written to `stdout`.
  ([PR](https://github.com/hashicorp/boundary/pull/962))
* cli: Error return codes have been standardized across CLI commands. An error
  code of `1` indicates an error generated from the actual controller API; an
  error code of `2` is an error encountered due to the CLI command's logic; and
  an error code of `3` indicates an error that was caused due to user input to
  the command. (There is some nuance sometimes whether an error is really due to
  user input or not, but we attempt to be consistent.)
  ([PR](https://github.com/hashicorp/boundary/pull/976))

### New and Improved

* list filtering: Listing now supports filtering results before being returned
  to the user. The filtering takes place server side and uses boolean
  expressions against the JSON representation of returned items. See [the
  documentation](https://www.developer.hashicorp.com/boundary/docs/filtering)
  for more details. ([PR 1](https://github.com/hashicorp/boundary/pull/952))
  ([PR 2](https://github.com/hashicorp/boundary/pull/957))
  ([PR 3](https://github.com/hashicorp/boundary/pull/967))
* server: Officially support reloading TLS parameters on `SIGHUP`. (This likely
  worked before but wasn't fully tested.)
  ([PR](https://github.com/hashicorp/boundary/pull/959))
* server: On `SIGHUP`, [worker
  tags](https://www.developer.hashicorp.com/boundary/docs/workers/worker-tags) will be
  re-parsed and new values used
  ([PR](https://github.com/hashicorp/boundary/pull/959))
* server: In addition to the existing `tls_min_version` listener configuration
  value, `tls_max_version` is now supported. This should generally be left blank
  but can be useful for situations where e.g. a load balancer has broken TLS 1.3
  support, or does not support TLS 1.3 and flags it as a disallowed value.

## 0.1.7 (2021/02/16)

*Note:* This release fixes an upgrade issue affecting users on Postgres 11
upgrading to 0.1.5 or 0.1.6 and makes a modification to the `boundary dev`
environment. It is otherwise identical to 0.1.6; see the entry for that version
for more details.

### Changes/Deprecations

* `boundary dev` now uses Postgres 11 by default, rather than Postgres 12.

### Bug Fixes

* server: Fix an issue with migrations affecting Postgres 11
  ([PR](https://github.com/hashicorp/boundary/pull/940))

## 0.1.6 (2021/02/12)

### Changes/Deprecations

* authentication: The `auth-methods/<id>:authenticate` action is deprecated and
  will be removed in a few releases. Instead, each auth method will define its
  own action or actions that are valid. This is necessary to support multi-step
  authentication schemes in upcoming releases. For the `password` auth method,
  the new action is `auth-methods/<id>:authenticate:login`.
* permissions: Update some errors to make them more descriptive, and disallow
  permissions in some forms where they will never take effect, preventing
  possible confusion (existing grants already saved to the database will not be
  affected as this is only filtered when grants are added/set on a role):
  * `id=<some_id>;actions=<some_actions>` where one of the actions is `create`
    or `list`. By definition this format operates only on individual resources
    so `create` and `list` will never work
  * `type=<some_type>;actions=<some_actions>` where one of the actions is _not_
    `create` or `list`. This format operates only on collections so assigning
    more actions this way will never work
* CORS: CORS is now turned on by default when running with `boundary server`
  with a `cors_allowed_origins` value of `serve://boundary`. You can disable it
  with `cors_enabled = false`, or if you want to change parameters, set
  `cors_enabled = true` and the other related configuration values.

### New and Improved

* server: When running single-server mode and `controllers` is not specified in
  the `worker` block, use `public_cluster_addr` if given
  ([PR](https://github.com/hashicorp/boundary/pull/904))
* server: `public_cluster_addr` in the `controller` block can now be specified
  as a `file://` or `env://` URL to read the value from a file or env var
  ([PR](https://github.com/hashicorp/boundary/pull/907))
* server: Add `read` action to default scope grant
  ([PR](https://github.com/hashicorp/boundary/pull/913))
* server: `public_cluster_addr` in the `controller` block can now be specified
  as a `file://` or `env://` URL to read the value from a file or env var
  ([PR](https://github.com/hashicorp/boundary/pull/907))
* sessions: Add `read:self` and `cancel:self` actions and enable them by default
  (in new project scopes) for all sessions. This allows a user to read or cancel
  any session that is associated with their user ID. `read` and `cancel` actions
  are still available that allow performing these actions on sessions that are
  associated with other users.

### Bug Fixes

* api: Fix nil pointer panic that could occur when using TLS
  ([Issue](https://github.com/hashicorp/boundary/pull/902),
  [PR](https://github.com/hashicorp/boundary/pull/901))
* server: When shutting down a controller release the shared advisory lock with
  a non-canceled context.
  ([Issue](https://github.com/hashicorp/boundary/pull/909),
  [PR](https://github.com/hashicorp/boundary/pull/918))
* targets: If a worker filter references a key that doesn't exist, treat it as a
  non-match rather than an error
  ([PR](https://github.com/hashicorp/boundary/pull/900))

## 0.1.5 (2021/01/29)

*NOTE*: This version requires a database migration via the new `boundary
database migrate` command.

### Security

* Boundary now uses Go's new execabs package for execution of binaries in
  `boundary connect`. This is for defense-in-depth rather than a specific
  issue. See the [Go blog post](https://blog.golang.org/path-security) for more
  details. ([PR](https://github.com/hashicorp/boundary/pull/873))

### Changes/Deprecations

* controller/worker: Require names to be all lowercase. This removes ambiguity
  or accidental mismatching when using upcoming filtering features.
* api/cli: Due to visibility changes on collection listing, a list will not
  include any resources if the user only has `list` as an authorized action. As
  a result `scope list`, which is used by the UI to populate the login scope
  dropdown, will be empty if the role granting the `u_anon` user `list`
  privileges is not updated to also contain a `read` action

### New and Improved

* targets: You can now specify a Boolean-expression filter against worker tags
  to control which workers are allowed to handle any given target's sessions
  ([PR](https://github.com/hashicorp/boundary/pull/862))
* api/cli: On listing/reading, return a list of actions the user is authorized
  to perform on the identified resources or their associated collections
  ([PR](https://github.com/hashicorp/boundary/pull/870))
* api/cli: Most resource types now support recursive listing, allowing listing
  to occur down a scope tree
  ([PR](https://github.com/hashicorp/boundary/pull/885))
* cli: Add a `database migrate` command which updates a database's schema to the
  version supported by the boundary binary
  ([PR](https://github.com/hashicorp/boundary/pull/872)).

### Bug Fixes

* controller/db: Correctly check if db init previously completed successfully
  when starting a controller or when running `database init`
  ([Issue](https://github.com/hashicorp/boundary/issues/805))
  ([PR](https://github.com/hashicorp/boundary/pull/842))
* cli: When `output-curl-string` is used with `update` or `add-/remove-/set-`
  commands and automatic versioning is being used (that is, no `-version` flag
  is given), it will now display the final call instead of the `GET` that
  fetches the current version
  ([Issue](https://github.com/hashicorp/boundary/issues/856))
  ([PR](https://github.com/hashicorp/boundary/pull/858))
* db: Fix panic in `database init` when controller config block is missing
  ([Issue](https://github.com/hashicorp/boundary/issues/819))
  ([PR](https://github.com/hashicorp/boundary/pull/851))

## 0.1.4 (2021/01/05)

### New and Improved

* controller: Improved error handling in iam repo
  ([PR](https://github.com/hashicorp/boundary/pull/841))
* controller: Improved error handling in db
  ([PR](https://github.com/hashicorp/boundary/pull/815))

### Bug Fixes

* servers: Fix erronious global unicast check that disallowed valid addresses
  from being assigned ([PR](https://github.com/hashicorp/boundary/pull/845))
* cli: Fix (hopefully) panic some users experience depending on their Linux
  setup when running the binary
  ([Issue](https://github.com/hashicorp/boundary/issues/830))
  ([PR](https://github.com/hashicorp/boundary/pull/846))

## 0.1.3 (2020/12/18)

### Changes/Deprecations

* controller: Switch the session connection limit for dev mode and the initial
  target when doing database initialization to `-1`. This makes it easier for
  people to start understanding Boundary while not hitting issues related to
  some programs/protocols needing multiple connections as they may not be easy
  for new users to understand.
  ([PR](https://github.com/hashicorp/boundary/pull/814))

### New and Improved

* controller, worker, cli: When the client quits before the session time is
  over, but in a manner where the TOFU token will be locked, attempt canceling
  the session rather than leaving it open to time out
  ([PR](https://github.com/hashicorp/boundary/pull/831))
* controller: Improved error handling in hosts, host catalog and host set
  ([PR](https://github.com/hashicorp/boundary/pull/786))
* controller: Relax account login name constraints to allow dash as valid
  character ([Issue](https://github.com/hashicorp/boundary/issues/759))
  ([PR](https://github.com/hashicorp/boundary/pull/806))
* cli/connect/http: Pass endpoint address through to allow setting TLS server
  name directly in most cases
  ([PR](https://github.com/hashicorp/boundary/pull/811))
* cli/connect/kube: New `kube` subcommand for `boundary connect` that makes it
  easy to route `kubectl` commands through Boundary, including when using
  `kubectl proxy` ([PR](https://github.com/hashicorp/boundary/pull/816))
* cli/server: Add some extra checks around valid/invalid combinations of
  addresses to avoid hard-to-understand runtime issues
  ([PR](https://github.com/hashicorp/boundary/pull/838))

### Bug Fixes

* cli: Ensure errors print to stderr when token is not found
  ([Issue](https://github.com/hashicorp/boundary/issues/791))
  ([PR](https://github.com/hashicorp/boundary/pull/799))
* controller: Fix grant IDs being lowercased when being read back (and when
  being used for permission evaluation)
  ([Issue](https://github.com/hashicorp/boundary/issues/794))
  ([PR](https://github.com/hashicorp/boundary/pull/839))

## 0.1.2 (2020/11/17)

### New and Improved

* docker: Official Docker image for `hashicorp/boundary`
  ([PR](https://github.com/hashicorp/boundary/pull/755))
* controller: Add ability to set public address for cluster purposes
  ([Issue](https://github.com/hashicorp/boundary/pull/758))
  ([PR](https://github.com/hashicorp/boundary/pull/761))
* ui: Improve scope awareness and navigation, including IAM for global scope
  ([PR](https://github.com/hashicorp/boundary-ui/pull/355))
* ui: Add dark mode toggle
  ([Issue](https://github.com/hashicorp/boundary/issues/719))
  ([PR](https://github.com/hashicorp/boundary-ui/pull/358))
* ui: Add scope grants to roles
  ([PR](https://github.com/hashicorp/boundary-ui/pull/357))
* ui: Add IAM resources to global scope
  ([PR](https://github.com/hashicorp/boundary-ui/pull/351))

### Bug Fixes

* controller, worker: Fix IPv4-only check so `0.0.0.0` specified without a port
  only listens on IPv4
  ([PR](https://github.com/hashicorp/boundary/pull/752))
* ui: Fix grant string corruption on updates
  ([Issue](https://github.com/hashicorp/boundary/issues/757))
  ([PR](https://github.com/hashicorp/boundary-ui/pull/356))
* controller, cli: Fix mutual exclusivity bug with using -authz-token on `boundary connect`
  ([PR](https://github.com/hashicorp/boundary/pull/787))

## 0.1.1 (2020/10/22)

### Changes/Deprecations

Note: in addition to changes marked below in this section, be aware that
currently names of resources are case-sensitive, but in a future update they
will become case-preserving but case-insensitive for comparisons (e.g. if using
them to access targets).

* cli: There are two changes to token storage handling:
  * Specifying `none` for the `-token-name` parameter has been deprecated in
    favor of specifying `none` for the new `-keyring-type` parameter.
  * [`pass`](https://www.passwordstore.org/) is now the default keyring type on
    non-Windows/non-macOS platforms. See the [CLI docs
    page](https://www.developer.hashicorp.com/boundary/docs/commands) for more
    information.

### New and Improved

* cli: New `-keyring-type` option and `pass` keyring type for token storage
  ([Issue](https://github.com/hashicorp/boundary/issues/697))
  ([PR](https://github.com/hashicorp/boundary/issues/731))
* connect: Allow using `-target-name` in conjunction with either
  `-target-scope-id` or `-target-scope-name` to connect to targets, rather than
  the target's ID
  ([PR](https://github.com/hashicorp/boundary/pull/737))
* controller: Allow API/Cluster listeners to be Unix domain sockets
  ([Issue](https://github.com/hashicorp/boundary/pull/699))
  ([PR](https://github.com/hashicorp/boundary/pull/705))
* ui: Allow creating and assigning a host to a host set directly from the host
  set view
  ([Issue](https://github.com/hashicorp/boundary/issues/710))
  ([PR](https://github.com/hashicorp/boundary-ui/pull/350))

### Bug Fixes

* cli: Fix database init when locale isn't English
  ([Issue](https://github.com/hashicorp/boundary/issues/729))
  ([PR](https://github.com/hashicorp/boundary/pull/736))
* cli: Fix hyphenation in help output for resources with compound names
  ([Issue](https://github.com/hashicorp/boundary/issues/686))
  ([PR](https://github.com/hashicorp/boundary/pull/689))
* controller: Allow connecting to Postgres when using remote Docker in dev mode
  ([Issue](https://github.com/hashicorp/boundary/issues/720)
  ([PR](https://github.com/hashicorp/boundary/pull/732))
* controller, worker: Fix listening on IPv6 addresses
  ([Issue](https://github.com/hashicorp/boundary/issues/701))
  ([PR](https://github.com/hashicorp/boundary/pull/703))
* worker: Fix setting controller address for worker in dev mode
  ([Issue](https://github.com/hashicorp/boundary/issues/727))
  ([PR](https://github.com/hashicorp/boundary/pull/705))

## 0.1.0 (2020/10/14)

v0.1.0 is the first release of Boundary. As a result there are no changes,
improvements, or bugfixes from past versions.
