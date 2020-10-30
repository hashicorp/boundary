package errors

// ParameterDetails provides the Name and Description of the invalid parameter
// error.
type ParameterDetails struct {
	Name        string
	Description string
}

// InvalidParametersWrapper extends Err with a list of ParameterDetails with
// further information about which parameters are invalid and a description of
// why.
type InvalidParametersWrapper struct {
	*Err
	Details []ParameterDetails
}

// NewInvalidParameterWrapper creates a new InvalidParametersWrapper using the
// list of details provide and supports the same options as errors.New, except
// for WithWrap which will always be ErrInvalidParameter for the wrapper.
func NewInvalidParametersWrapper(details []ParameterDetails, opt ...Option) error {
	err := New(InvalidParameter, opt...).(*Err)
	err.Wrapped = ErrInvalidParameter
	e := &InvalidParametersWrapper{
		Err:     err,
		Details: details,
	}
	return e
}
