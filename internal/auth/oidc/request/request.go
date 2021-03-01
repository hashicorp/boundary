package request

import "github.com/hashicorp/boundary/internal/errors"

// Validate the State
func (s *State) Validate() error {
	const op = "request.(State).Validate"
	if s.TokenRequestId == "" {
		return errors.New(errors.InvalidParameter, op, "missing token request id")
	}
	if s.CreateTime == nil {
		return errors.New(errors.InvalidParameter, op, "missing create time")
	}
	if s.ExpirationTime == nil {
		return errors.New(errors.InvalidParameter, op, "missing expiration time")

	}
	if s.FinalRedirectUrl == "" {
		return errors.New(errors.InvalidParameter, op, "missing final redirect URL")
	}
	if s.Nonce == "" {
		return errors.New(errors.InvalidParameter, op, "missing nonce")
	}
	if s.ProviderConfigHash == 0 {
		return errors.New(errors.InvalidParameter, op, "missing provider config hash")
	}
	return nil
}

// Validate the Wrapper
func (w *Wrapper) Validate() error {
	const op = "request.(Wrapper).Validate"
	if w.AuthMethodId == "" {
		return errors.New(errors.InvalidParameter, op, "missing auth method id")

	}
	if w.ScopeId == "" {
		return errors.New(errors.InvalidParameter, op, "missing scope id")

	}
	if w.WrapperKeyId == "" {
		return errors.New(errors.InvalidParameter, op, "missing wrapper key id")

	}
	if len(w.Ct) == 0 {
		return errors.New(errors.InvalidParameter, op, "missing ct")

	}
	return nil
}
