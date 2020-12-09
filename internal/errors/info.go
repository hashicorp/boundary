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
	RecordNotFound: {
		Message: "record not found",
		Kind:    Search,
	},
	MultipleRecords: {
		Message: "multiple records",
		Kind:    Search,
	},
}
