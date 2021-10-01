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
			Pointer:        "/Attributes/Fields/token_type",
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
		// secret fields
		{
			Pointer:        "/Attributes/Fields/token",
			Classification: encrypt.SecretClassification,
		},
	}, nil
}
