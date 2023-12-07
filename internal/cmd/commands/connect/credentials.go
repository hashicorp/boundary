// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package connect

import (
	"errors"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/mitchellh/mapstructure"
)

type usernamePassword struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	raw      *targets.SessionCredential
	consumed bool
}

type sshPrivateKey struct {
	Username   string `mapstructure:"username"`
	PrivateKey string `mapstructure:"private_key"`
	Passphrase string `mapstructure:"private_key_passphrase"`

	raw      *targets.SessionCredential
	consumed bool
}

type credentials struct {
	usernamePassword []usernamePassword
	sshPrivateKey    []sshPrivateKey
	unspecified      []*targets.SessionCredential
}

func (c credentials) unconsumedSessionCredentials() []*targets.SessionCredential {
	out := make([]*targets.SessionCredential, 0, len(c.sshPrivateKey)+len(c.usernamePassword)+len(c.unspecified))

	// Unspecified credentials cannot be consumed
	out = append(out, c.unspecified...)

	for _, c := range c.sshPrivateKey {
		if !c.consumed {
			out = append(out, c.raw)
		}
	}
	for _, c := range c.usernamePassword {
		if !c.consumed {
			out = append(out, c.raw)
		}
	}
	return out
}

func parseCredentials(creds []*targets.SessionCredential) (credentials, error) {
	if creds == nil {
		return credentials{}, nil
	}
	var out credentials
	for _, cred := range creds {
		if cred.CredentialSource == nil {
			return credentials{}, errors.New("missing credential source")
		}

		var upCred usernamePassword
		var spkCred sshPrivateKey
		switch credential.Type(cred.CredentialSource.CredentialType) {
		case credential.UsernamePasswordType:
			// Decode attributes from credential struct
			if err := mapstructure.Decode(cred.Credential, &upCred); err != nil {
				return credentials{}, err
			}

			if upCred.Username != "" && upCred.Password != "" {
				upCred.raw = cred
				out.usernamePassword = append(out.usernamePassword, upCred)
				continue
			}

		case credential.SshPrivateKeyType:
			// Decode attributes from credential struct
			if err := mapstructure.Decode(cred.Credential, &spkCred); err != nil {
				return credentials{}, err
			}

			if spkCred.Username != "" && spkCred.PrivateKey != "" {
				spkCred.raw = cred
				out.sshPrivateKey = append(out.sshPrivateKey, spkCred)
				continue
			}
		}

		// Credential type is unspecified, make a best effort attempt to parse
		// a credential from the Decoded field if it exists
		if cred.Secret != nil && cred.Secret.Decoded != nil {
			// Attempt unmarshaling into username password creds
			if err := mapstructure.Decode(cred.Secret.Decoded, &upCred); err != nil {
				return credentials{}, err
			}
			if upCred.Username != "" && upCred.Password != "" {
				upCred.raw = cred
				out.usernamePassword = append(out.usernamePassword, upCred)
				continue
			}

			// Attempt unmarshaling into ssh private key creds
			if err := mapstructure.Decode(cred.Secret.Decoded, &spkCred); err != nil {
				return credentials{}, err
			}
			if spkCred.Username != "" && spkCred.PrivateKey != "" {
				spkCred.raw = cred
				out.sshPrivateKey = append(out.sshPrivateKey, spkCred)
				continue
			}
		}

		// We could not parse the credential
		out.unspecified = append(out.unspecified, cred)
	}

	return out, nil
}
