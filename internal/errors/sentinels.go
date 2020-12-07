package errors

// Errors returned from this package may be tested against these errors
// with errors.Is. Creating new Sentinel type errors like these should be
// deprecated in favor of the new Err type that includes unique Codes and a
// Matching function.
var (
	// ErrInvalidPublicId indicates an invalid PublicId.
	ErrInvalidPublicId = E(WithCode(InvalidParameter), WithMsg("invalid publicId"))

	// ErrInvalidParameter is returned by create and update methods if
	// an attribute on a struct contains illegal or invalid values.
	ErrInvalidParameter = E(WithCode(InvalidParameter), WithMsg("invalid parameter"))

	// ErrInvalidFieldMask is returned by update methods if the field mask
	// contains unknown fields or fields that cannot be updated.
	ErrInvalidFieldMask = E(WithCode(InvalidParameter), WithMsg("invalid field mask"))

	// ErrEmptyFieldMask is returned by update methods if the field mask is
	// empty.
	ErrEmptyFieldMask = E(WithCode(InvalidParameter), WithMsg("empty field mask"))

	// ErrNotUnique is returned by create and update methods when a write
	// to the repository resulted in a unique constraint violation.
	ErrNotUnique = E(WithCode(NotUnique), WithMsg("unique constraint violation"))

	// ErrNotNull is returned by methods when a write to the repository resulted
	// in a check constraint violation
	ErrCheckConstraint = E(WithCode(CheckConstraint), WithMsg("check constraint violated"))

	// ErrNotNull is returned by methods when a write to the repository resulted
	// in a not null constraint violation
	ErrNotNull = E(WithCode(NotNull), WithMsg("not null constraint violated"))

	// ErrRecordNotFound returns a "record not found" error and it only occurs
	// when attempting to read from the database into struct.
	// When reading into a slice it won't return this error.
	ErrRecordNotFound = E(WithCode(RecordNotFound), WithMsg("record not found"))

	// ErrMultipleRecords is returned by update and delete methods when a
	// write to the repository would result in more than one record being
	// changed resulting in the transaction being rolled back.
	ErrMultipleRecords = E(WithCode(MultipleRecords), WithMsg("multiple records"))
)
