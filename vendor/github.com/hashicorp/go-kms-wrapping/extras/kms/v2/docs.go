// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// kms is a package that provides key management system features for
// go-kms-wrapping Wrappers.
//
// The following domain terms are key to understanding the system and how to use
// it:
//
//   - wrapper: all keys within the system are a Wrapper from go-kms-wrapping.
//
//   - root external wrapper: the external wrapper that will serve as the root of
//     trust for the kms system.  Typically you'd get this root wrapper via
//     go-kms-wrapper from a KMS provider.  See the go-kms-wrapper docs for further
//     details.
//
//   - scope: a scope defines a rotational boundary for a set of keys.  The system
//     tracks only the scope identifier and which is used to find keys with a
//     specific scope.
//
//     **IMPORTANT**: You should define a FK from kms_root_key.scope_id with
//     cascading deletes and updates to the PK of the table within your domain that
//     tracks scopes.  This FK will prevent orphaned kms keys.
//
//     For example, you could assign organizations and projects
//     scope IDs and then associate a set of keys with each org and project within
//     your domain.
//
//   - root key:  the KEKs (keys to encrypt keys) of the system.
//
//   - data key:  the DEKs (keys to encrypt data) of the system and must have a
//     parent root key and a purpose.
//
//   - purpose:  Each data key (DEK) must have a one purpose.  For
//     example, you could define a purpose of client-secrets for a DEK that will be
//     used encrypt/decrypt wrapper operations on `client-secrets`
//
// # Database Schema
//
// You'll find the database schema within the migrations directory.
// Currently postgres and sqlite are supported.  The implementation does make some
// use of triggers to ensure some of its data integrity.
//
// The migrations are intended to be incorporated into your existing go-migrate
// migrations.  Feel free to change the migration file names, as long as they are
// applied in the same order as defined here.  FYI, the migrations include
// `kms_version` table which is used to ensure that the schema and module are
// compatible.
//
// # High-level ERD
//
//	             ┌───────────────────────────────┐
//	             │                               ○
//	             ┼                               ┼
//	┌────────────────────────┐      ┌────────────────────────┐
//	│      kms_root_key      │      │      kms_data_key      │
//	├────────────────────────┤      ├────────────────────────┤
//	│private_id              │      │private_id              │
//	│scope_id                │      │root_key_id             │
//	│                        │      │purpose                 │
//	└────────────────────────┘      │                        │
//	             ┼                  └────────────────────────┘
//	             │                               ┼
//	             │                               │
//	             │                               │
//	             │                               │
//	             ┼                               ┼
//	            ╱│╲                             ╱│╲
//	┌────────────────────────┐      ┌────────────────────────┐
//	│  kms_root_key_version  │      │  kms_data_key_version  │
//	├────────────────────────┤      ├────────────────────────┤
//	│private_id              │      │private_id              │
//	│root_key_id             │      │data_key_id             │
//	│key                     │      │root_key_id             │
//	│version                 │      │key                     │
//	│                        │      │version                 │
//	└────────────────────────┘      └────────────────────────┘
//	             ┼                               ┼
//	             │                               ○
//	             └───────────────────────────────┘
package kms
