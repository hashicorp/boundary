# Boundary CHANGELOG

Canonical reference for changes, improvements, and bugfixes for Boundary.

## Next

### Deprecations/Changes

* authentication: The `auth-methods/<id>:authenticate:login` action is
  deprecated and will be removed in a few releases. (Yes, this was meant to
  deprecate the `authenticate` action; apologies for going back on this!) To
  better support future auth methods, and especially the potential for plugins,
  rather than defining custom actions on the URL path the `authenticate` action
  will consume both a map of parameters but also a `command` parameter that
  specifies the type of command. This allows workflows that require multiple
  steps, such as OIDC, to not require custom subactions. Additionally, the
  `credentials` map in the `authenticate` action has been renamed `attributes`
  to better match other types of resources. `credentials` will still work for
  now but will be removed in a few releases. Finally, in the Go SDK, the
  `Authenticate` function now requires a `command` value to be passed in.
* Related to the above change, the output of an API
  `auth-methods/<id>:authenticate` call will return the given `command` value
  and a map of attributes that depend on the given command. On the SDK side, the
  output of the `Authenticate` function returns a map, from which a concrete
  type can be easily umarshaled (see the updated `authenticate password` command
  for an example).

### New and Improved

* cli/api/sdk: New OIDC auth method type added with support for create, read,
  update, delete, and list (see new cli `oidc` subcommands available on CRUDL
  operations for examples).
  [PR](https://github.com/hashicorp/boundary/pull/1090)    
* cli: support to login using an OIDC auth method (see the new `authenticate
  password oidc` subcommand for an example) 
  [PR](https://github.com/hashicorp/boundary/pull/1090)
* server: When performing recursive listing, `list` action is not longer
  required to be granted to the calling user. Instead, the given scope acts as
  the root point (so only results under that scope will be shown), and `list`
  grant is evaluated per-scope.
  [PR](https://github.com/hashicorp/boundary/pull/1016)
* database init: If the database is already initialized, return 0 as the exit
  code. This matches how the `database migrate` command works.
  [PR](https://github.com/hashicorp/boundary/pull/1033)

### Bug Fixes

* server: Roles for auto generated scopes are now generated at database init.
  [PR](https://github.com/hashicorp/boundary/pull/996)

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
  [PR](https://github.com/hashicorp/boundary/pull/962)
* cli: In `json` output format, a resource item is now an object under the
  top-level key `item`; a list of resource items is now an list of objects under
  the top-level key `items`. This preserves the top level for putting in other
  useful information later on (and the HTTP status code is included now).
  [PR](https://github.com/hashicorp/boundary/pull/962)
* cli: In `json` output format, errors are now serialized as a JSON object with
  an `error` key instead of outputting normal text
  [PR](https://github.com/hashicorp/boundary/pull/962)
* cli: All errors, including API errors, are now written to `stderr`. Previously
  in the default table format, API errors would be written to `stdout`.
  [PR](https://github.com/hashicorp/boundary/pull/962)
* cli: Error return codes have been standardized across CLI commands. An error
  code of `1` indicates an error generated from the actual controller API; an
  error code of `2` is an error encountered due to the CLI command's logic; and
  an error code of `3` indicates an error that was caused due to user input to
  the command. (There is some nuance sometimes whether an error is really due to
  user input or not, but we attempt to be consistent.)
  [PR](https://github.com/hashicorp/boundary/pull/976)

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
  with an `allowed_origins` value of `serve://boundary`. You can disable it with
  `cors_enabled = false`, or if you want to change parameters, set `cors_enabled
  = true` and the other related configuration values.

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
  a non-cancelled context.
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
* api/cli: Due to visibility changes on collection listing, a list
  will not include any resources if the user only has `list` as an authorized action.
  As a result `scope list`, which is used by the UI to populate the login scope dropdown, 
  will be empty if the role granting the `u_anon` user `list` privileges is not updated to also contain a `read` action

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
* cli: Add a `database migrate` command which updates a database's schema to 
  the version supported by the boundary binary ([PR](https://github.com/hashicorp/boundary/pull/872)).

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
* controller: Relax account login name constraints to allow dash as valid character 
  ([Issue](https://github.com/hashicorp/boundary/issues/759))
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
