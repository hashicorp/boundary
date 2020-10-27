package errors

// InvalidParameterWrapper extends Err with Name and Description fields for the
// invalid parameter error.
type InvalidParameterWrapper struct {
	*Err
	// Name of the invalid parameter
	Name string
	// Description of why the parameter's value is invalid
	Description string
}

// NewInvalidParameterWrapper creates a new InvalidParameterWrapper and supports
// the same options as errors.New, except for WithWrap which will always be
// ErrInvalidParameter for the wrapper, while adding the fields for parameter
// name and parameter
// description.
func NewInvalidParameterWrapper(parameterName, parameterDescription string, opt ...Option) error {
	err := New(InvalidParameter, opt...).(*Err)
	err.Wrapped = ErrInvalidParameter
	e := &InvalidParameterWrapper{
		Err:         err,
		Name:        parameterName,
		Description: parameterDescription,
	}
	return e
}
