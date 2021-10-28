package authmethods

import (
	"fmt"

	"github.com/hashicorp/eventlogger/filters/encrypt"
)

// Tags implements the encrypt.Taggable interface which allows
// AuthMethod map fields to be classified for the encrypt filter.
func (req *AuthMethod) Tags() ([]encrypt.PointerTag, error) {
	tags := make([]encrypt.PointerTag, 0, len(req.AuthorizedCollectionActions))
	for k := range req.AuthorizedCollectionActions {
		tags = append(tags, encrypt.PointerTag{
			Pointer:        fmt.Sprintf("/AuthorizedCollectionActions/%s", k),
			Classification: encrypt.PublicClassification,
		})
	}
	if req.Attributes != nil {
		switch req.Type {
		case "oidc":
			oidcTags := []encrypt.PointerTag{
				// public fields
				{
					Pointer:        "/Attributes/Fields/state",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/issuer",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/client_id",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/client_secret_hmac",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/max_age",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/signing_algorithms",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/idp_ca_certs",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/api_url_prefix",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/callback_url",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/allowed_audiences",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/claims_scopes",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/account_claim_maps",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/disable_discovered_config_validation",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/dry_run",
					Classification: encrypt.PublicClassification,
				},
				// secrets
				{
					Pointer:        "/Attributes/Fields/client_secret",
					Classification: encrypt.SecretClassification,
				},
			}
			tags = append(tags, oidcTags...)
		case "password":
			pwTags := []encrypt.PointerTag{
				{
					Pointer:        "/Attributes/Fields/min_login_name_length",
					Classification: encrypt.PublicClassification,
				},
				{
					Pointer:        "/Attributes/Fields/min_password_length",
					Classification: encrypt.PublicClassification,
				},
			}
			tags = append(tags, pwTags...)
		}
	}
	return tags, nil
}
