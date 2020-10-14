package errors

// Template that's useful constructing Match error templates, especially if you
// want to make an error match template without a Code.  Template satisfies the
// error interface via its embedded Error.
type Template struct {
	err  Error
	Kind Kind
}

// Info about the Template
func (t *Template) Info() Info {
	if t.err.Code != Unknown {
		return t.err.Info()
	}
	return Info{
		Message: "Unknown",
		Kind:    t.Kind,
	}
}

// Error satisfies the error interface but intentional don't return anything of
// value, since Templates should not be used for domain errors.
func (t *Template) Error() string {
	return "Template error"
}

// T creates a new Template for matching
func T(args ...interface{}) *Template {
	t := &Template{}
	for _, a := range args {
		switch arg := a.(type) {
		case Code:
			t.err.Code = arg
		case string:
			t.err.Msg = arg
		case Op:
			t.err.Op = arg
		case *Error: // order is important, this match must before "case error:"
			c := *arg
			t.err.Wrapped = &c
		case error:
			t.err.Wrapped = arg
		case Kind:
			t.Kind = arg
		default:
			// ignore it
		}
	}
	return t
}

// Match the template against the err.  The err must be a *Error or match will
// return false.  Matches all non-empty fields of the template against the err.
func Match(t *Template, err error) bool {
	if t == nil {
		return false
	}
	e, ok := err.(*Error)
	if !ok {
		return false
	}

	if t.err.Code != Unknown && t.err.Code != e.Code {
		return false
	}
	if t.err.Msg != "" && t.err.Msg != e.Msg {
		return false
	}
	if t.err.Op != "" && t.err.Op != e.Op {
		return false
	}
	if t.Info().Kind != e.Info().Kind {
		return false
	}
	if t.err.Wrapped != nil {
		if wrappedT, ok := t.err.Wrapped.(*Template); ok {
			return Match(wrappedT, e.Wrapped)
		}
		if e.Wrapped != nil && t.err.Wrapped.Error() != e.Wrapped.Error() {
			return false
		}
	}

	return true
}
