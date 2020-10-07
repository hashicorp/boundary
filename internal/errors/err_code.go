package errors

// ErrClass specifies the class of error (unknown, parameter, integrity, etc).
type ErrClass uint32

// ErrCode specifies a code for the error.
type ErrCode uint32
type ErrInfo struct {
	Class   ErrClass
	Message string
}

const (
	UnknownErrClass ErrClass = 0
	ParameterError  ErrClass = 1
	IntegrityError  ErrClass = 2
	SearchError     ErrClass = 3
)

func (e ErrClass) String() string {
	return [...]string{
		"unknown",
		"parameter violation",
		"integrity violation",
		"search issue",
	}[e]
}

const (
	ErrCodeInvalidParameter ErrCode = 100
	ErrCodeCheckConstraint  ErrCode = 1000
	ErrCodeNotNull          ErrCode = 1001
	ErrCodeUnique           ErrCode = 1002
	ErrCodeRecordNotFound   ErrCode = 1100
	ErrCodeMultipleRecords  ErrCode = 1101
)

func (e ErrCode) String() string {
	if i, ok := errorCodeInfo[e]; ok {
		return i.Message
	}
	return "unknown"
}

var errorCodeInfo = map[ErrCode]ErrInfo{
	ErrCodeInvalidParameter: {
		Message: "invalid parameter",
		Class:   ParameterError,
	},
	ErrCodeCheckConstraint: {
		Message: "constraint check failed",
		Class:   IntegrityError,
	},
	ErrCodeNotNull: {
		Message: "must not be empty (null) violation",
		Class:   IntegrityError,
	},
	ErrCodeUnique: {
		Message: "must be unique violation",
		Class:   IntegrityError,
	},
	ErrCodeRecordNotFound: {
		Message: "record not fouind",
		Class:   SearchError,
	},
	ErrCodeMultipleRecords: {
		Message: "multiple records",
		Class:   SearchError,
	},
}
