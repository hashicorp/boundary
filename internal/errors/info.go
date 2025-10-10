// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package errors

// Info contains details of the specific error code
type Info struct {
	// Kind specifies the kind of error (unknown, parameter, integrity, etc).
	Kind Kind

	// Message provides a default message for the error code
	Message string
}

// errorCodeInfo provides a map of unique Codes (IDs) to their
// corresponding Kind and a default Message.
var errorCodeInfo = map[Code]Info{
	Unknown: {
		Message: "unknown",
		Kind:    Other,
	},
	InvalidParameter: {
		Message: "invalid parameter",
		Kind:    Parameter,
	},
	InvalidAddress: {
		Message: "invalid address",
		Kind:    Parameter,
	},
	InvalidPublicId: {
		Message: "invalid public id",
		Kind:    Parameter,
	},
	InvalidFieldMask: {
		Message: "invalid field mask",
		Kind:    Parameter,
	},
	EmptyFieldMask: {
		Message: "empty field mask",
		Kind:    Parameter,
	},
	KeyNotFound: {
		Message: "key/version not found",
		Kind:    Integrity,
	},
	InvalidTextRepresentation: {
		Message: "invalid text representation",
		Kind:    Integrity,
	},
	TicketAlreadyRedeemed: {
		Message: "ticket already redeemed",
		Kind:    Integrity,
	},
	TicketNotFound: {
		Message: "ticket not found",
		Kind:    Integrity,
	},
	Io: {
		Message: "error during io operation",
		Kind:    Integrity,
	},
	InvalidTimeStamp: {
		Message: "invalid time stamp",
		Kind:    Integrity,
	},
	SessionNotFound: {
		Message: "session not found",
		Kind:    Integrity,
	},
	InvalidSessionState: {
		Message: "session state was not valid for the requested operation",
		Kind:    Integrity,
	},
	TokenMismatch: {
		Message: "token mismatch",
		Kind:    Integrity,
	},
	TooShort: {
		Message: "too short",
		Kind:    Integrity,
	},
	AuthMethodInactive: {
		Message: "authentication method is inactive",
		Kind:    State,
	},
	AuthAttemptExpired: {
		Message: "authentication attempt has expired",
		Kind:    State,
	},
	AccountAlreadyAssociated: {
		Message: "account already associated with another user",
		Kind:    Parameter,
	},
	InvalidJobRunState: {
		Message: "job run is already in a final run state",
		Kind:    Integrity,
	},
	JobAlreadyRunning: {
		Message: "job already running",
		Kind:    State,
	},
	SubtypeAlreadyRegistered: {
		Message: "subtype already registered",
		Kind:    Parameter,
	},
	InvalidDynamicCredential: {
		Message: "dynamic credential for session is in an invalid state",
		Kind:    Integrity,
	},
	PasswordTooShort: {
		Message: "too short",
		Kind:    Password,
	},
	PasswordUnsupportedConfiguration: {
		Message: "unable to support the password config type",
		Kind:    Password,
	},
	PasswordInvalidConfiguration: {
		Message: "invalid parameters in password configuration",
		Kind:    Password,
	},
	PasswordsEqual: {
		Message: "old and new password are equal",
		Kind:    Password,
	},
	Encrypt: {
		Message: "error occurred during encrypt",
		Kind:    Encryption,
	},
	Decrypt: {
		Message: "error occurred during decrypt",
		Kind:    Encryption,
	},
	Encode: {
		Message: "error occurred during encode",
		Kind:    Encoding,
	},
	Decode: {
		Message: "error occurred during decode",
		Kind:    Encoding,
	},
	GenKey: {
		Message: "error occurred during key generation",
		Kind:    Encryption,
	},
	GenCert: {
		Message: "error occurred during certification generation",
		Kind:    Encryption,
	},
	Sign: {
		Message: "error occurred during signing",
		Kind:    Encryption,
	},
	Verify: {
		Message: "error occurred during verification",
		Kind:    Encryption,
	},
	Internal: {
		Message: "internal error",
		Kind:    Other,
	},
	Forbidden: {
		Message: "forbidden",
		Kind:    Other,
	},
	Unauthorized: {
		Message: "unauthorized",
		Kind:    Other,
	},
	Conflict: {
		Message: "conflict",
		Kind:    Integrity,
	},
	CheckConstraint: {
		Message: "constraint check failed",
		Kind:    Integrity,
	},
	NotNull: {
		Message: "must not be empty (null) violation",
		Kind:    Integrity,
	},
	NotUnique: {
		Message: "must be unique violation",
		Kind:    Integrity,
	},
	NotSpecificIntegrity: {
		Message: "Integrity violation without specific details",
		Kind:    Integrity,
	},
	MissingTable: {
		Message: "missing table",
		Kind:    Integrity,
	},
	ColumnNotFound: {
		Message: "column not found",
		Kind:    Integrity,
	},
	RecordNotFound: {
		Message: "record not found",
		Kind:    Search,
	},
	MultipleRecords: {
		Message: "multiple records",
		Kind:    Search,
	},
	Exception: {
		Message: "db exception",
		Kind:    Integrity,
	},
	VersionMismatch: {
		Message: "version mismatch",
		Kind:    Integrity,
	},
	MaxRetries: {
		Message: "too many retries",
		Kind:    Transaction,
	},
	MigrationIntegrity: {
		Message: "migration integrity",
		Kind:    Integrity,
	},
	MigrationLock: {
		Message: "bad db lock",
		Kind:    Integrity,
	},
	Unavailable: {
		Message: "external system unavailable",
		Kind:    External,
	},
	VaultTokenNotOrphan: {
		Message: "vault token is not an orphan token",
		Kind:    VaultToken,
	},
	VaultTokenNotPeriodic: {
		Message: "vault token is not a periodic token",
		Kind:    VaultToken,
	},
	VaultTokenNotRenewable: {
		Message: "vault token is not renewable",
		Kind:    VaultToken,
	},
	VaultTokenMissingCapabilities: {
		Message: "vault token is missing capabilities",
		Kind:    VaultToken,
	},
	VaultCredentialRequest: {
		Message: "request for a new credential from vault failed",
		Kind:    External,
	},
	VaultEmptySecret: {
		Message: "vault secret is empty",
		Kind:    Integrity,
	},
	VaultInvalidMappingOverride: {
		Message: "invalid credential mapping override",
		Kind:    Parameter,
	},
	VaultInvalidCredentialMapping: {
		Message: "mapping vault secret to a credential type failed",
		Kind:    Integrity,
	},
	OidcProviderCallbackError: {
		Message: "oidc provider callback error",
		Kind:    External,
	},
	GracefullyAborted: {
		Message: "purposefully aborted without error",
		Kind:    Other,
	},
	ImmutableColumn: {
		Message: "immutable column",
		Kind:    Integrity,
	},
	UnexpectedRowsAffected: {
		Message: "unexpected number of rows affected",
		Kind:    Integrity,
	},
	NoPathFound: {
		Message: "no path found",
		Kind:    State,
	},
	WorkerNotFound: {
		Message: "worker not found",
		Kind:    State,
	},
	CycleFound: {
		Message: "cycle found",
		Kind:    State,
	},
	WorkerConnNotFound: {
		Message: "worker connection not found",
		Kind:    State,
	},
	KmsWorkerUnsupportedOperation: {
		Message: "unsupported operation for a kms worker",
		Kind:    State,
	},
	WorkerNotFoundForRequest: {
		Message: "worker not found with all conditions required for request",
		Kind:    State,
	},
	QueueIsFull: {
		Message: "queue is full",
		Kind:    State,
	},
	RetryLimitExceeded: {
		Message: "retry limit exceeded",
		Kind:    State,
	},
	NotFound: {
		Message: "not found",
		Kind:    State,
	},
	StorageFileClosed: {
		Message: "file is closed",
		Kind:    State,
	},
	StorageContainerClosed: {
		Message: "container is closed",
		Kind:    State,
	},
	StorageFileReadOnly: {
		Message: "file is read only",
		Kind:    State,
	},
	StorageFileWriteOnly: {
		Message: "file is write only",
		Kind:    State,
	},
	StorageFileAlreadyExists: {
		Message: "file already exists",
		Kind:    State,
	},
	StorageContainerReadOnly: {
		Message: "container is read only",
		Kind:    State,
	},
	StorageContainerWriteOnly: {
		Message: "container is write only",
		Kind:    State,
	},
	Closed: {
		Message: "closed",
		Kind:    State,
	},
	Paused: {
		Message: "paused",
		Kind:    State,
	},
	WindowsRDPClientEarlyDisconnection: {
		Message: "rdp client disconnected early",
		Kind:    State,
	},
	ExternalPlugin: {
		Message: "plugin error",
		Kind:    External,
	},
	ChecksumMismatch: {
		Message: "checksum mismatch",
		Kind:    Integrity,
	},
	InvalidConfiguration: {
		Message: "invalid configuration",
		Kind:    Configuration,
	},
	InvalidListToken: {
		Message: "invalid list token",
		Kind:    Parameter,
	},
}
