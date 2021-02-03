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
}
