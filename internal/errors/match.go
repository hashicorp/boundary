package errors

// Template is useful constructing Match Err templates.  Templates allow you to
// match Errs without specifying a Code.  In other words, just Match using the
// Errs: Kind, Op, etc.
type Template struct {
	Err
	Kind Kind
}

// Info about the Template, which is useful when matching a Template's Kind with
// an Err's Kind.
func (t *Template) Info() Info {
	if t.Code != Unknown {
		return t.Info()
	}
	return Info{
		Message: "Unknown",
		Kind:    t.Kind,
	}
}

// Error satisfies the error interface but we intentionally don't return
// anything of value, in an effort to stop users from substituting Templates in
// place of Errs, when creating domain errors.
func (t *Template) Error() string {
	return "Template error"
}

// T creates a new Template for matching Errs
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

// Match the template against the error.  The error must be a *Err, or match
// will return false.  Matches all non-empty fields of the template against the
// error.
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
