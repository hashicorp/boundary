package errors

type ParamaterDetails struct {
	Name        string
	Description string
}

// InvalidParametersWrapper extends Err with Name and Description fields for the
// invalid parameter error.
type InvalidParametersWrapper struct {
	*Err
	Details []ParamaterDetails
}

// NewInvalidParameterWrapper creates a new InvalidParametersWrapper and supports
// the same options as errors.New, except for WithWrap which will always be
// ErrInvalidParameter for the wrapper, while adding the Details about list of
// parameters that were invalid.
func NewInvalidParametersWrapper(details []ParamaterDetails, opt ...Option) error {
	err := New(InvalidParameter, opt...).(*Err)
	err.Wrapped = ErrInvalidParameter
	e := &InvalidParametersWrapper{
		Err:     err,
		Details: details,
	}
	return e
}
