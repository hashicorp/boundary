package errors

// Errors returned from this package may be tested against these errors
// with errors.Is. Creating new Sentinel type errors like these should be
// deprecated in favor of the new Err type that includes unique Codes and a
// Matching function.
var (
	// ErrInvalidPublicId indicates an invalid PublicId.
	ErrInvalidPublicId = New(InvalidParameter, WithMsg("invalid publicId"))

	// ErrInvalidParameter is returned by create and update methods if
	// an attribute on a struct contains illegal or invalid values.
	ErrInvalidParameter = New(InvalidParameter, WithMsg("invalid parameter"))

	// ErrInvalidFieldMask is returned by update methods if the field mask
	// contains unknown fields or fields that cannot be updated.
	ErrInvalidFieldMask = New(InvalidParameter, WithMsg("invalid field mask"))

	// ErrEmptyFieldMask is returned by update methods if the field mask is
	// empty.
	ErrEmptyFieldMask = New(InvalidParameter, WithMsg("empty field mask"))

	// ErrNotUnique is returned by create and update methods when a write
	// to the repository resulted in a unique constraint violation.
	ErrNotUnique = New(NotUnique, WithMsg("unique constraint violation"))

	// ErrNotNull is returned by methods when a write to the repository resulted
	// in a check constraint violation
	ErrCheckConstraint = New(CheckConstraint, WithMsg("check constraint violated"))

	// ErrNotNull is returned by methods when a write to the repository resulted
	// in a not null constraint violation
	ErrNotNull = New(NotNull, WithMsg("not null constraint violated"))

	// ErrRecordNotFound returns a "record not found" error and it only occurs
	// when attempting to read from the database into struct.
	// When reading into a slice it won't return this error.
	ErrRecordNotFound = New(RecordNotFound, WithMsg("record not found"))

	// ErrMultipleRecords is returned by update and delete methods when a
	// write to the repository would result in more than one record being
	// changed resulting in the transaction being rolled back.
	ErrMultipleRecords = New(MultipleRecords, WithMsg("multiple records"))
)
