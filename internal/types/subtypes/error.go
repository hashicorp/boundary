package subtypes

import "fmt"

type InvalidArgumentError struct {
	Op        string
	FieldName string
	Msg       string
}

func NewInvalidArgumentError(op, fieldName, msg string) error {
	return &InvalidArgumentError{
		Op:        op,
		FieldName: fieldName,
		Msg:       msg,
	}
}

func (e *InvalidArgumentError) Error() string {
	return fmt.Sprintf("%s: %s", e.Op, e.Msg)
}
