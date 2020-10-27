package errors

type InvalidParameterWrapper struct {
	*Err
	Name        string
	Description string
}

func NewInvalidParameterWrapper(parameterName, parameterDescription string, opt ...Option) error {
	err := New(InvalidParameter, opt...).(*Err)
	e := &InvalidParameterWrapper{
		Err:         err,
		Name:        parameterName,
		Description: parameterDescription,
	}
	return e
}
