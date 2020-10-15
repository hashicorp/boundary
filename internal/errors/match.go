package errors

// Template that's useful constructing Match error templates, especially if you
// want to make an error match template without a errors.Code.
type Template struct {
	Err
	Kind Kind
}

// Info about the Template
func (t *Template) Info() Info {
	if t.Code != Unknown {
		return t.Info()
	}
	return Info{
		Message: "Unknown",
		Kind:    t.Kind,
	}
}

// Error satisfies the error interface but intentional don't return anything of
// value, since Templates should not be used for domain errors. (We've
// intentionally overriden the embedded Err.Error() for the same reason).
func (t *Template) Error() string {
	return "Template error"
}

// T creates a new Template for matching
func T(args ...interface{}) *Template {
	t := &Template{}
	for _, a := range args {
		switch arg := a.(type) {
		case Code:
			t.Code = arg
		case string:
			t.Msg = arg
		case Op:
			t.Op = arg
		case *Err: // order is important, this match must before "case error:"
			c := *arg
			t.Wrapped = &c
		case error:
			t.Wrapped = arg
		case Kind:
			t.Kind = arg
		default:
			// ignore it
		}
	}
	return t
}

// Match the template against the err.  The err must be a *Err or match will
// return false.  Matches all non-empty fields of the template against the err.
func Match(t *Template, err error) bool {
	if t == nil {
		return false
	}
	e, ok := err.(*Err)
	if !ok {
		return false
	}

	if t.Code != Unknown && t.Code != e.Code {
		return false
	}
	if t.Msg != "" && t.Msg != e.Msg {
		return false
	}
	if t.Op != "" && t.Op != e.Op {
		return false
	}
	if t.Info().Kind != e.Info().Kind {
		return false
	}
	if t.Wrapped != nil {
		if wrappedT, ok := t.Wrapped.(*Template); ok {
			return Match(wrappedT, e.Wrapped)
		}
		if e.Wrapped != nil && t.Wrapped.Error() != e.Wrapped.Error() {
			return false
		}
	}

	return true
}
