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
	InvalidParameter Code = 100 // InvalidParameter represents and invalid parameter for an operation.
	InvalidAddress   Code = 101
	InvalidPublicId  Code = 102

	// DB errors are resevered Codes from 1000-1999
	CheckConstraint      Code = 1000 // CheckConstraint represents a check constraint error
	NotNull              Code = 1001 // NotNull represents a value must not be null error
	NotUnique            Code = 1002 // NotUnique represents a value must be unique error
	NotSpecificIntegrity Code = 1003 // NotSpecificIntegrity represents an integrity error that has no specificy domain error code
	MissingTable         Code = 1004 // Missing table represents an undefined table error
	RecordNotFound       Code = 1100 // RecordNotFound represents that a record/row was not found matching the criteria
	MultipleRecords      Code = 1101 // MultipleRecords represents that multiple records/rows were found matching the criteria

)
