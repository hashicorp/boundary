package errors

// Kind specifies the kind of error (unknown, parameter, integrity, etc).
type Kind uint32

// Code specifies a code for the error.
type Code uint32
type Info struct {
	Kind    Kind
	Message string
}

const (
	Other Kind = iota
	Parameter
	Integrity
	Search
)

func (e Kind) String() string {
	return map[Kind]string{
		Other:     "unknown",
		Parameter: "parameter violation",
		Integrity: "integrity violation",
		Search:    "search issue",
	}[e]
}

const (
	InvalidParameter Code = 100
	CheckConstraint  Code = 1000
	NotNull          Code = 1001
	NotUnique        Code = 1002
	RecordNotFound   Code = 1100
	MultipleRecords  Code = 1101
)

func (e Code) String() string {
	if i, ok := errorCodeInfo[e]; ok {
		return i.Message
	}
	return "unknown"
}

var errorCodeInfo = map[Code]Info{
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
