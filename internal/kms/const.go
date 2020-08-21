package kms

// KeyPurpose allows an application to specify the reason they need a key; this
// is used to select which DEK to return
type KeyPurpose uint

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

	// KeyPurposeSessions is used as a base key to derive session-specific keys
	KeyPurposeSessions
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
	case KeyPurposeSessions:
		return "sessions"
	default:
		return "unknown"
	}
}
