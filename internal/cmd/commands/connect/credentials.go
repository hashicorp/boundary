package connect

import (
	"errors"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/mitchellh/mapstructure"
)

type usernamePasswordCredentials struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// TODO: this should support multiple types of credentials and return an interface instead
// of only usernamepassword. Each subcommand can use the returned credentials as it needs.
func parseCredentials(creds []*targets.SessionCredential) ([]usernamePasswordCredentials, error) {
	if creds == nil {
		return nil, nil
	}
	var out []usernamePasswordCredentials
	for _, cred := range creds {
		if cred.CredentialSource == nil {
			return nil, errors.New("missing credential source")
		}

		var c usernamePasswordCredentials
		if cred.CredentialSource.CredentialType == string(credential.UsernamePasswordType) {
			// Decode attributes from credential struct
			if err := mapstructure.Decode(cred.Credential, &c); err != nil {
				return nil, err
			}

			if c.Username != "" && c.Password != "" {
				out = append(out, c)
				continue
			}
		}

		// Credential type is unspecified, make a best effort attempt to parse both username
		// and password from Decoded field if it exists
		if cred.Secret == nil || cred.Secret.Decoded == nil {
			// No secret data continue to next credential
			continue
		}

		switch cred.CredentialSource.Type {
		case "vault", "static":
			// Attempt unmarshaling into creds
			if err := mapstructure.Decode(cred.Secret.Decoded, &c); err != nil {
				return nil, err
			}
		}

		if c.Username != "" && c.Password != "" {
			out = append(out, c)
		}
	}
	return out, nil
}
