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
	InvalidParameter      Code = 100 // InvalidParameter represents an invalid parameter for an operation.
	InvalidAddress        Code = 101 // InvalidAddress represents an invalid host address for an operation
	InvalidPublicId       Code = 102 // InvalidPublicId represents an invalid public Id for an operation
	InvalidFieldMask      Code = 103 // InvalidFieldMask represents an invalid field mast for an operation
	EmptyFieldMask        Code = 104 // EmptyFieldMask represents an empty field mask for an operation
	KeyNotFound           Code = 105 // KeyNotFound represents that a key/version was not found in the KMS
	TicketAlreadyRedeemed Code = 106 // TicketAlreadyRedeemed represents that the ticket version has already been redeemed
	TicketNotFound        Code = 107 // TicketNotFound represents that the ticket was not found
	Io                    Code = 108 // Io represents that an io error occurred in an underlying call (i.e binary.Write)
	SessionNotFound       Code = 109 // SessionNotFound represents that the session was not found
	InvalidSessionState   Code = 110 // InvalidSessionState represents that the session was in an invalid state
	TokenMismatch         Code = 111 // TokenMismatch represents that the ticket was not found

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

	// Migration setup errors are codes 2000-3000
	MigrationIntegrity Code = 2000 // MigrationIntegrity represents an error with the generated migration related code
	MigrationLock      Code = 2001 // MigrationLock represents an error related to locking of the DB
)
