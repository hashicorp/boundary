package services

import "github.com/hashicorp/eventlogger/filters/encrypt"

// Tags implements the encrypt.Taggable interface which allows
// AuthenticateResponse Attributes to be classified for the encrypt filter.
func (req *AuthenticateResponse) Tags() ([]encrypt.PointerTag, error) {
	if req.Attributes == nil {
		return nil, nil
	}
	return []encrypt.PointerTag{
		// public fields
		{
			Pointer:        "/Attributes/Fields/account_id",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/approximate_last_used_time",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/auth_method_id",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/authorized_actions",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/created_time",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/expiration_time",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/id",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/scope",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/type",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/updated_time",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/user_id",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/status",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/auth_url",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/token_id",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/final_redirect_url",
			Classification: encrypt.PublicClassification,
		},
		// secret fields
		{
			Pointer:        "/Attributes/Fields/token",
			Classification: encrypt.SecretClassification,
		},
	}, nil
}

// Tags implements the encrypt.Taggable interface which allows
// AuthenticateRequest Attributes to be classified for the encrypt filter.
func (req *AuthenticateRequest) Tags() ([]encrypt.PointerTag, error) {
	if req.Attributes == nil {
		return nil, nil
	}
	return []encrypt.PointerTag{
		// public fields
		{
			Pointer:        "/Attributes/Fields/login_name",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/auth_url",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/token_id",
			Classification: encrypt.PublicClassification,
		},
		{
			Pointer:        "/Attributes/Fields/state",
			Classification: encrypt.PublicClassification,
		},
		// secret fields
		{
			Pointer:        "/Attributes/Fields/password",
			Classification: encrypt.SecretClassification,
		},
		{
			Pointer:        "/Attributes/Fields/code",
			Classification: encrypt.SecretClassification,
		},
	}, nil
}

// Tags implements the encrypt.Taggable interface which allows
// ChangeStateRequest Attributes to be classified for the encrypt filter.
func (req *ChangeStateRequest) Tags() ([]encrypt.PointerTag, error) {
	if req.Attributes == nil {
		return nil, nil
	}
	return []encrypt.PointerTag{
		// public fields
		{
			Pointer:        "/Attributes/Fields/state",
			Classification: encrypt.PublicClassification,
		},
	}, nil
}
