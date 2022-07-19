package connect

import (
	"errors"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/mitchellh/mapstructure"
)

type usernamePasswordCredential struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type sshPrivateKeyCredential struct {
	Username   string `mapstructure:"username"`
	PrivateKey string `mapstructure:"private_key"`
}

func parseCredentials(creds []*targets.SessionCredential) ([]any, error) {
	if creds == nil {
		return nil, nil
	}
	var out []any
	for _, cred := range creds {
		if cred.CredentialSource == nil {
			return nil, errors.New("missing credential source")
		}

		var upCred usernamePasswordCredential
		var spkCred sshPrivateKeyCredential
		switch credential.Type(cred.CredentialSource.CredentialType) {
		case credential.UsernamePasswordType:
			// Decode attributes from credential struct
			if err := mapstructure.Decode(cred.Credential, &upCred); err != nil {
				return nil, err
			}

			if upCred.Username != "" && upCred.Password != "" {
				out = append(out, upCred)
				continue
			}

		case credential.SshPrivateKeyType:
			// Decode attributes from credential struct
			if err := mapstructure.Decode(cred.Credential, &spkCred); err != nil {
				return nil, err
			}

			if spkCred.Username != "" && spkCred.PrivateKey != "" {
				out = append(out, spkCred)
				continue
			}
		}

		// Credential type is unspecified, make a best effort attempt to parse
		// the Decoded field if it exists
		if cred.Secret == nil || cred.Secret.Decoded == nil {
			// No secret data continue to next credential
			continue
		}

		switch cred.CredentialSource.Type {
		case "vault", "static":
			// Attempt unmarshaling into username password creds
			if err := mapstructure.Decode(cred.Secret.Decoded, &upCred); err != nil {
				return nil, err
			}
			if upCred.Username != "" && upCred.Password != "" {
				out = append(out, upCred)
				continue
			}

			// Attempt unmarshaling into ssh private key creds
			if err := mapstructure.Decode(cred.Secret.Decoded, &spkCred); err != nil {
				return nil, err
			}
			if spkCred.Username != "" && spkCred.PrivateKey != "" {
				out = append(out, spkCred)
				continue
			}
		}
	}

	return out, nil
}
