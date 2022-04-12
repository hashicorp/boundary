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

	// KeyPurposeTokens is used for token encryption
	KeyPurposeTokens

	// KeyPurposeSessions is used as a base key to derive session-specific encryption keys
	KeyPurposeSessions

	// KeyPurposeOidc is used for encrypting oidc states included in
	// authentication URLs
	KeyPurposeOidc

	// KeyPurposeAudit is used for audit operations
	KeyPurposeAudit
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
	case KeyPurposeTokens:
		return "tokens"
	case KeyPurposeSessions:
		return "sessions"
	case KeyPurposeOidc:
		return "oidc"
	case KeyPurposeAudit:
		return "audit"
	default:
		return "unknown"
	}
}

// KeyType allows the kms repo to return a map[KeyType]Key which can be easily
// used without type casting.
type KeyType uint

const (
	KeyTypeUnknown KeyType = iota
	KeyTypeRootKey
	KeyTypeRootKeyVersion
	KeyTypeDatabaseKey
	KeyTypeDatabaseKeyVersion
	KeyTypeOplogKey
	KeyTypeOplogKeyVersion
	KeyTypeTokenKey
	KeyTypeTokenKeyVersion
	KeyTypeSessionKey
	KeyTypeSessionKeyVersion
	KeyTypeOidcKey
	KeyTypeOidcKeyVersion
	KeyTypeAuditKey
	KeyTypeAuditKeyVersion
)

// String returns the key type cast as a string, just so it can be called as
// a function instead of direct casting elsewhere, yw
func (k KeyType) String() string {
	switch k {
	case KeyTypeRootKey:
		return "rootKey"
	case KeyTypeRootKeyVersion:
		return "rootKeyVersion"
	case KeyTypeDatabaseKey:
		return "databaseKey"
	case KeyTypeDatabaseKeyVersion:
		return "databaseKeyVersion"
	case KeyTypeOplogKey:
		return "oplogKey"
	case KeyTypeOplogKeyVersion:
		return "oplogKeyVersion"
	case KeyTypeTokenKey:
		return "tokenKey"
	case KeyTypeTokenKeyVersion:
		return "tokenKeyVersion"
	case KeyTypeSessionKey:
		return "sessionKey"
	case KeyTypeSessionKeyVersion:
		return "sessionKeyVersion"
	case KeyTypeOidcKey:
		return "oidcKey"
	case KeyTypeOidcKeyVersion:
		return "oidcKeyVersion"
	case KeyTypeAuditKey:
		return "auditKey"
	case KeyTypeAuditKeyVersion:
		return "auditKeyVersion"

	default:
		return "unknown"
	}
}
