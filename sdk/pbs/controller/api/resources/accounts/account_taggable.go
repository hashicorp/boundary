package accounts

import (
	"github.com/hashicorp/eventlogger/filters/encrypt"
)

func (a *Account) Tags() ([]encrypt.PointerTag, error) {
	if a.Attributes == nil {
		return nil, nil
	}

	switch a.Type {
	case "password":
		return []encrypt.PointerTag{
			{
				Pointer:        "/Attributes/Fields/login_name",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/password",
				Classification: encrypt.SecretClassification,
			},
		}, nil
	case "oidc":
		return []encrypt.PointerTag{
			// `OidcAccountAttributes` Top-Level Fields
			{
				Pointer:        "/Attributes/Fields/issuer",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/subject",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/full_name",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/email",
				Classification: encrypt.SensitiveClassification,
			},

			// Passthrough to the bottom fields because the library doesn't seem to understand the relationship
			// between fields - If this is not here, it'll apply the transformation to the fields correctly as
			// defined below, but then it'll redact all over them again because it picks on these top-level
			// fields, thinks they're an entirely different thing.
			//
			// Note: This is not a "default" data classification. If there's more fields within these items that we
			// haven't specified, they'll still get redacted. AFAIK, this tells the library to, when it sees this
			// particular field, leave it undisturbed.
			//
			// Not sure if bug or feature...
			{
				Pointer:        "/Attributes/Fields/token_claims",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims",
				Classification: encrypt.PublicClassification,
			},

			// OpenID Connect Token Claims
			// UserInfo Claims can also appear here.
			// TODO(hugo): This is a subset of all possible JWT Claims - Should we go with https://www.iana.org/assignments/jwt/jwt.xhtml?
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/iss",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/sub",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/aud",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/exp",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/iat",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/auth_time",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/nonce",
				Classification: encrypt.SecretClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/auth_time",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/acr",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/amr",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/azp",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/at_hash",
				Classification: encrypt.SecretClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/c_hash",
				Classification: encrypt.SecretClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/name",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/given_name",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/family_name",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/middle_name",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/nickname",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/preferred_username",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/profile",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/picture",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/website",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/email",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/email_verified",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/gender",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/birthdate",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/zoneinfo",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/locale",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/phone_number",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/phone_number_verified",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/address",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/token_claims/Kind/StructValue/Fields/updated_at",
				Classification: encrypt.PublicClassification,
			},

			// OpenID Connect UserInfo Claims
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/sub",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/name",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/given_name",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/family_name",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/middle_name",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/nickname",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/preferred_username",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/profile",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/picture",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/website",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/email",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/email_verified",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/gender",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/birthdate",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/zoneinfo",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/locale",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/phone_number",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/phone_number_verified",
				Classification: encrypt.PublicClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/address",
				Classification: encrypt.SensitiveClassification,
			},
			{
				Pointer:        "/Attributes/Fields/userinfo_claims/Kind/StructValue/Fields/updated_at",
				Classification: encrypt.PublicClassification,
			},
		}, nil
	}

	return nil, nil
}
