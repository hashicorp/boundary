package errors

type Info struct {
	Kind    Kind
	Message string
}

var errorCodeInfo = map[Code]Info{
	Unknown: {
		Message: "unknown",
		Kind:    Other,
	},
	InvalidParameter: {
		Message: "invalid parameter",
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
	RecordNotFound: {
		Message: "record not fouind",
		Kind:    Search,
	},
	MultipleRecords: {
		Message: "multiple records",
		Kind:    Search,
	},
}
