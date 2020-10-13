package errors

// Code specifies a code for the error.
type Code uint32

const (
	Unknown          Code = 0
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
