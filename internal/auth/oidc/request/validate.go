package request

import "github.com/hashicorp/boundary/internal/errors"

// Validate the request.State
func (s *State) Validate() error {
	const op = "request.(State).Validate"
	if s == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing state")
	}
	if s.TokenRequestId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing token request id")
	}
	if s.CreateTime == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing create time")
	}
	if s.ExpirationTime == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing expiration time")
	}
	if s.FinalRedirectUrl == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing final redirect URL")
	}
	if s.Nonce == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing nonce")
	}
	if s.ProviderConfigHash == 0 {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing provider config hash")
	}
	return nil
}

// Validate the request.Wrapper
func (w *Wrapper) Validate() error {
	const op = "request.(Wrapper).Validate"
	if w == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing wrapper")
	}
	if w.AuthMethodId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing auth method id")
	}
	if w.ScopeId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing scope id")
	}
	if w.WrapperKeyId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing wrapper key id")
	}
	if len(w.Ct) == 0 {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing ct")
	}
	return nil
}

// Validate the request.Token
func (t *Token) Validate() error {
	const op = "request.(Token).Validate"
	if t == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing token")
	}
	if t.RequestId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing request id")
	}
	if t.ExpirationTime == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing expiration time")
	}
	return nil
}
