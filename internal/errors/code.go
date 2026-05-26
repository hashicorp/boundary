// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package errors

// Code specifies a code for the error.
type Code uint32

// String will return the Code's Info.Message
func (c Code) String() string {
	return c.Info().Message
}

// Info will look up the Code's Info.  If the Info is not found, it will return
// Info for an Unknown Code.
func (c Code) Info() Info {
	if info, ok := errorCodeInfo[c]; ok {
		return info
	}
	return errorCodeInfo[Unknown]
}

const (
	Unknown Code = 0 // Unknown will be equal to a zero value for Codes

	// General function errors are reserved Codes 100-999
	InvalidParameter              Code = 100 // InvalidParameter represents an invalid parameter for an operation.
	InvalidAddress                Code = 101 // InvalidAddress represents an invalid host address for an operation
	InvalidPublicId               Code = 102 // InvalidPublicId represents an invalid public Id for an operation
	InvalidFieldMask              Code = 103 // InvalidFieldMask represents an invalid field mask for an operation
	EmptyFieldMask                Code = 104 // EmptyFieldMask represents an empty field mask for an operation
	KeyNotFound                   Code = 105 // KeyNotFound represents that a key/version was not found in the KMS
	TicketAlreadyRedeemed         Code = 106 // TicketAlreadyRedeemed represents that the ticket version has already been redeemed
	TicketNotFound                Code = 107 // TicketNotFound represents that the ticket was not found
	Io                            Code = 108 // Io represents that an io error occurred in an underlying call (i.e binary.Write)
	InvalidTimeStamp              Code = 109 // InvalidTimeStamp represents an invalid time stamp for an operation
	SessionNotFound               Code = 110 // SessionNotFound represents that the session was not found
	InvalidSessionState           Code = 111 // InvalidSessionState represents that the session was in an invalid state
	TokenMismatch                 Code = 112 // TokenMismatch represents that there was a token mismatch
	TooShort                      Code = 113 // TooShort represents an error that means the provided input is not meeting minimum length requirements
	AccountAlreadyAssociated      Code = 114 // AccountAlreadyAssociated represents an attempt to associate an account failed since it was already associated.
	InvalidJobRunState            Code = 115 // InvalidJobRunState represents that a JobRun was in an invalid state
	InvalidDynamicCredential      Code = 116 // InvalidDynamicCredential represents that a dynamic credential for a session was in an invalid state
	JobAlreadyRunning             Code = 117 // JobAlreadyRunning represents that a Job is already running when an attempt to run again was made
	SubtypeAlreadyRegistered      Code = 118 // SubtypeAlreadyRegistered represents that a value has already been registered in the subtype registry system.
	NoPathFound                   Code = 119 // NoPathFound represents an error when no path is found to a worker
	WorkerNotFound                Code = 120 // WorkerNotFound represents an error when a worker is not found in the graph of downstream workers
	CycleFound                    Code = 121 // CycleFound represents an error when a cycle is found between a parent and child worker
	WorkerConnNotFound            Code = 122 // WorkerConnNotFound represents an error when a connection to a worker is not found
	KmsWorkerUnsupportedOperation Code = 123 // KmsWorkerUnsupportedOperation represents an error when a KMS worker is not supported for an operation

	// Note: Currently unused in OSS
	RetryLimitExceeded Code = 124 // RetryLimitExceeded represents an error when a retry limit is exceeded
	// Note: Currently unused in OSS
	QueueIsFull Code = 125 // QueueIsFull results in attempting to add an item to a queue which is full

	// Note: Storage errors are currently unused in OSS
	StorageFileClosed         Code = 126 // StorageFileClose represents an error when a file has been closed and a read/write operation is attempted on it
	StorageContainerClosed    Code = 127 // StorageContainerClosed represents an error when a container has been closed and a I/O operation is attempted on it
	StorageFileReadOnly       Code = 128 // StorageFileReadOnly represents an error when a file is readonly and a write operation is attempted on it
	StorageFileWriteOnly      Code = 129 // StorageFileWriteOnly represents an error when a file is write only and a read operation is attempted on it
	StorageFileAlreadyExists  Code = 130 // StorageFileAlreadyExists represents an error when a file already exists during an attempt to create it
	StorageContainerReadOnly  Code = 131 // StorageContainerReadOnly represents an error when a container is readonly and a write operation is attempted on it
	StorageContainerWriteOnly Code = 132 // StorageContainerWriteOnly represents an error when a container is write only and a read operation is attempted on it

	WorkerNotFoundForRequest Code = 133 // WorkerNotFoundForRequest represents an error when no appropriate worker is found which meets the conditions required to handle a request
	Closed                   Code = 134 // Closed represents an error when an operation cannot be completed because the thing being operated on is closed
	ChecksumMismatch         Code = 135 // ChecksumMismatch represents an error when a checksum is mismatched
	InvalidListToken         Code = 136 // InvalidListToken represents an error where the provided list token is invalid
	Paused                   Code = 137 // Paused represents an error when an operation cannot be completed because the thing being operated on is paused

	// Note: Currently unused in OSS
	WindowsRDPClientEarlyDisconnection Code = 138 // WindowsRDPClientEarlyDisconnection represents an error when a Windows RDP client disconnects early, a known behavior with Windows Remote Desktop clients

	AuthAttemptExpired Code = 198 // AuthAttemptExpired represents an expired authentication attempt
	AuthMethodInactive Code = 199 // AuthMethodInactive represents an error that means the auth method is not active.

	// PasswordTooShort results from attempting to set a password which is to short.
	PasswordTooShort Code = 200

	// PasswordUnsupportedConfiguration results from attempting to perform an
	// operation that sets a password configuration to an unsupported type.
	PasswordUnsupportedConfiguration Code = 201

	// PasswordInvalidConfiguration results from attempting to perform an
	// operation that sets a valid password configuration with invalid settings.
	PasswordInvalidConfiguration Code = 202

	// PasswordsEqual is returned from ChangePassword when the old and
	// new passwords are equal.
	PasswordsEqual Code = 203

	Encrypt Code = 300 // Encrypt represents an error occurred during the underlying encryption process
	Decrypt Code = 301 // Decrypt represents an error occurred during the underlying decryption process
	Encode  Code = 302 // Encode represents an error occurred during the underlying encoding/marshaling process
	Decode  Code = 303 // Decode represents an error occurred during the underlying decoding/unmarshaling process
	GenKey  Code = 304 // GenKey represents an error occurred during the underlying key generation process
	GenCert Code = 305 // GenCert represents an error occurred during the underlying certificate generation process
	Sign    Code = 306 // Sign represents an error occurred during the underlying signing process
	Verify  Code = 307 // Verify represents an error occurred during the underlying verification process

	// General system errors are reserved Codes 400-599 and align with http
	// client and server error codes
	Unauthorized Code = 401 // Unauthorized represents the operation is unauthorized
	Forbidden    Code = 403 // Forbidden represents the operation is forbidden
	NotFound     Code = 404 // NotFound represents an operation which is unable to find the requested item.
	Conflict     Code = 409 // Conflict represents the operation failed due to failed pre-condition or was aborted.
	Internal     Code = 500 // InternalError represents the system encountered an unexpected condition.

	// DB errors are reserved Codes from 1000-1999
	CheckConstraint      Code = 1000 // CheckConstraint represents a check constraint error
	NotNull              Code = 1001 // NotNull represents a value must not be null error
	NotUnique            Code = 1002 // NotUnique represents a value must be unique error
	NotSpecificIntegrity Code = 1003 // NotSpecificIntegrity represents an integrity error that has no specific domain error code
	MissingTable         Code = 1004 // MissingTable represents an undefined table error
	RecordNotFound       Code = 1100 // RecordNotFound represents that a record/row was not found matching the criteria
	MultipleRecords      Code = 1101 // MultipleRecords represents that multiple records/rows were found matching the criteria
	ColumnNotFound       Code = 1102 // ColumnNotFound represent that a column was not found in the underlying db
	MaxRetries           Code = 1103 // MaxRetries represent that a db Tx hit max retires allowed
	Exception            Code = 1104 // Exception represent that an underlying db exception was raised
	VersionMismatch      Code = 1105 // VersionMismatch represents the update version and the db version for an entry do not match.
	// GracefullyAborted means we intended to abort a transaction but the
	// enclosing function should not treat it as an error; we aborted for
	// reasons related to the state of the DDL and/or inputs (such as we're
	// already in the right state and don't want to end up writing oplogs).
	GracefullyAborted Code = 1106
	// UnexpectedRowsAffected indicates that an action expected to operate on a
	// specific number of records returned a different count, e.g. if you
	// expected to delete three items and only one was deleted.
	UnexpectedRowsAffected Code = 1107
	// ImmutableColumn is used when an operation attempted to mutate an immutable column.
	ImmutableColumn Code = 1108
	// InvalidTextRepresentation represents a value does not have the correct text representation.
	InvalidTextRepresentation Code = 1109

	// Migration setup errors are codes 2000-2999
	MigrationIntegrity Code = 2000 // MigrationIntegrity represents an error with the generated migration related code
	MigrationLock      Code = 2001 // MigrationLock represents an error related to locking of the DB

	// External system errors are reserved codes 3000-3999
	Unavailable    Code = 3000 // Unavailable represents that an external system is unavailable
	ExternalPlugin Code = 3001 // ExternalPlugin represent an error that occurred on a plugin external to Boundary

	// Vault specific errors
	VaultTokenNotOrphan           Code = 3010 // VaultTokenNotOrphan represents an error for a Vault token that is not an orphan token
	VaultTokenNotPeriodic         Code = 3011 // VaultTokenNotPeriodic represents an error for a Vault token that is not a periodic token
	VaultTokenNotRenewable        Code = 3012 // VaultTokenNotRenewable represents an error for a Vault token that is not renewable
	VaultTokenMissingCapabilities Code = 3013 // VaultTokenMissingCapabilities represents an error for a Vault token that is missing capabilities
	VaultCredentialRequest        Code = 3014 // VaultCredentialRequest represents an error returned from Vault when retrieving a credential
	VaultEmptySecret              Code = 3015 // VaultEmptySecret represents a empty secret was returned from Vault without error
	VaultInvalidMappingOverride   Code = 3016 // VaultInvalidMappingOverride represents an error returned when a credential mapping is unknown or does not match a credential type
	VaultInvalidCredentialMapping Code = 3017 // VaultInvalidCredentialMapping represents an error returned when a Vault secret failed to be mapped to a specific credential type

	// OIDC authentication provided errors
	OidcProviderCallbackError Code = 4000 // OidcProviderCallbackError represents an error that is passed by the OIDC provider to the callback endpoint

	// Configuration error codes
	InvalidConfiguration Code = 5000 // InvalidConfiguration represents an error with the configuration file.
)
