# Boundary CHANGELOG

Canonical reference for changes, improvements, and bugfixes for Boundary.

## vNext

### Changes/Deprecations

* cli: There are two changes to token storage handling:
  * Specifying `none` for the `token-name` parameter has been deprecated in
    favor of specifying `none` for the new `keyring-type` parameter.
  * [`pass`](https://www.passwordstore.org/) is now the default keyring type on
    non-Windows/non-macOS platforms. See the [CLI docs
    page](https://www.boundaryproject.io/docs/api-clients/cli) for more
    information.

### New and Improved

* cli: New `keyring-type` option and `pass` keyring type for token storage
  ([Issue](https://github.com/hashicorp/boundary/issues/697))
  ([PR](https://github.com/hashicorp/boundary/issues/731))
* controller: Allow API/Cluster listeners to be Unix domain sockets
  ([Issue](https://github.com/hashicorp/boundary/pull/699))
  ([PR](https://github.com/hashicorp/boundary/pull/705))

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

## v0.1.0

v0.1.0 is the first release of Boundary. As a result there are no changes,
improvements, or bugfixes from past versions.
