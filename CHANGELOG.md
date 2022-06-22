# Boundary CHANGELOG

Canonical reference for changes, improvements, and bugfixes for Boundary.

## Next

## 0.9.0 (2022/06/20)

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
  authorization time. [PR](https://github.com/hashicorp/boundary/pull/2174)
* `boundary connect` Credential Brokering Integration: we have extended integration
  into the `boundary connect` helpers. A new `sshpass` style has been added to the 
  `ssh` helper, when used, if the credential contains a username/password and `sshpass` 
  is installed, the command will automatically pass the credentials to the `ssh` process.
  Additionally, the default `ssh` helper will now use the `username` of the brokered credential.
  [PR](https://github.com/hashicorp/boundary/pull/2191).
* controller: Improve response time for listing sessions.
  This also creates a new periodic job that will delete terminated
  sessions after 1 hour.
  See Deprecations/Changes for some additional details.
  [PR](https://github.com/hashicorp/boundary/pull/2160).
* event filtering: Change event filters to use lowercase and snake case for data
  elements like the rest of Boundary filters do. 
* ui: Use include_terminated flag for listing sessions.
  [PR](https://github.com/hashicorp/boundary-ui/pull/1126).
* ui: Add Quick Setup onboarding guide.
  [PR](https://github.com/hashicorp/boundary-ui/pull/1140).

### Bug Fixes

* The plugin execution_dir configuration parameter is now respected.
  [PR](https://github.com/hashicorp/boundary/pull/2183).
* ui: Fix Users page not updating fields correctly.
  [PR](https://github.com/hashicorp/boundary-ui/pull/1105).

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
  [PR](https://github.com/hashicorp/boundary/pull/2160).
* Anonymous user permissions: In order to reduce the risk of accidental and
  unintended granting of permissions to anonymous users, the permissions system
  now only allows certain actions on certain resources to be assigned to the
  anonymous user; currently these are the same permissions as assigned in
  Boundary's default role permissions. If other use-cases arise this list can be
  expanded. See [the
  documentation](https://www.boundaryproject.io/docs/concepts/security/permissions/assignable-permissions)
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
  [PR](https://github.com/hashicorp/boundary/pull/2049)
* ui: Add support for worker filters in targets
* ui: Add manual refresh button in sessions list
* Audit events are no longer a WIP ([PR](https://github.com/hashicorp/boundary/pull/2031).

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
  [PR](https://github.com/hashicorp/boundary/pull/2049)
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
  [documentation](https://www.boundaryproject.io/docs) for configuration
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
  ([issue](https://github.com/hashicorp/boundary/issues/1488),
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
  groups](https://www.boundaryproject.io/docs/concepts/filtering/oidc-managed-groups).
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
    [filters](https://www.boundaryproject.io/docs/concepts/filtering) which are
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
  ([issue](https://github.com/hashicorp/boundary/issues/1305),
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
  ([issue](https://github.com/hashicorp/boundary/issues/1309),
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
  ([issue](https://github.com/hashicorp/cap/issues/37),
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
  documentation](https://www.boundaryproject.io/docs/concepts/security/permissions)
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
  documentation](https://www.boundaryproject.io/docs/concepts/filtering/resource-listing)
  for more details. ([PR 1](https://github.com/hashicorp/boundary/pull/952))
  ([PR 2](https://github.com/hashicorp/boundary/pull/957))
  ([PR 3](https://github.com/hashicorp/boundary/pull/967))
* server: Officially support reloading TLS parameters on `SIGHUP`. (This likely
  worked before but wasn't fully tested.)
  ([PR](https://github.com/hashicorp/boundary/pull/959))
* server: On `SIGHUP`, [worker
  tags](https://www.boundaryproject.io/docs/configuration/worker#tags) will be
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
    page](https://www.boundaryproject.io/docs/api-clients/cli) for more
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
