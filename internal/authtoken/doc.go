// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package authtoken provides an authtoken with an encrypted value and
// an associated expiration time.  It also provides a repository which
// manages the lifetime of the token.
//
// The auth token value is a base62 bit value with a version prefix. This
// value is encrypted at rest and is used to authenticate incoming requests
// to the controller.  It is associated with a public id which allows admins
// to operate on it without knowing the token itself.  It also has an
// expiration time and a last accessed time which are used to determine if the
// token can still be used.
//
// # Repository
//
// A repository provides methods for creating, validating a provided token value,
// and deleting the auth token.  At validation time if the token is determined
// to be expired or stale it will be removed from the backing storage by the repo.
package authtoken
