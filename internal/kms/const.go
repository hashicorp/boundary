// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

// KeyPurpose allows an application to specify the reason they need a key; this
// is used to select which DEK to return
type KeyPurpose uint

// ****************************************************************************
// IMPORTANT: if you're adding a new KeyPurpose, you should consider whether or
// not existing scopes need this new type of key.  If they do, then you may want
// to add the new key into kms.ReconcileKeys(...)
// ****************************************************************************
const (
	// KeyPurposeUnknown is the default, and indicates that a correct purpose
	// wasn't specified
	KeyPurposeUnknown KeyPurpose = iota

	// KeyPurposeDatabase is used for general encryption needs for most values
	// in the database, excluding the oplog
	KeyPurposeDatabase

	// KeyPurposeOplog is used for oplogs
	KeyPurposeOplog

	// KeyPurposeRecovery is used for recovery access
	KeyPurposeRecovery

	// KeyPurposeWorkerAuth is used for worker auth
	KeyPurposeWorkerAuth

	// KeyPurposeWorkerAuthStorage is used for worker credential storage
	KeyPurposeWorkerAuthStorage

	// KeyPurposeTokens is used for token encryption
	KeyPurposeTokens

	// KeyPurposeSessions is used as a base key to derive session-specific encryption keys
	KeyPurposeSessions

	// KeyPurposeOidc is used for encrypting oidc states included in
	// authentication URLs
	KeyPurposeOidc

	// KeyPurposeAudit is used for audit operations
	KeyPurposeAudit

	// KeyPurposeRootKey is used as the root key
	KeyPurposeRootKey

	// KeyPurpose is used for wrapping BSR keys
	KeyPurposeBsr
)

// String returns the key purpose cast as a string, just so it can be called as
// a function instead of direct casting elsewhere, yw
func (k KeyPurpose) String() string {
	switch k {
	case KeyPurposeDatabase:
		return "database"
	case KeyPurposeOplog:
		return "oplog"
	case KeyPurposeRecovery:
		return "recovery"
	case KeyPurposeWorkerAuth:
		return "workerauth"
	case KeyPurposeWorkerAuthStorage:
		return "workerauthstorage"
	case KeyPurposeTokens:
		return "tokens"
	case KeyPurposeSessions:
		return "sessions"
	case KeyPurposeOidc:
		return "oidc"
	case KeyPurposeAudit:
		return "audit"
	case KeyPurposeRootKey:
		return "rootKey"
	case KeyPurposeBsr:
		return "bsr"
	default:
		return "unknown"
	}
}

// ValidDekPurposes returns the current list of valid DEK key purposes
func ValidDekPurposes() []KeyPurpose {
	return []KeyPurpose{
		KeyPurposeDatabase,
		KeyPurposeOplog,
		KeyPurposeTokens,
		KeyPurposeSessions,
		KeyPurposeOidc,
		KeyPurposeAudit,
	}
}
