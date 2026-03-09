// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"errors"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/mitchellh/mapstructure"
)

const (
	usernamePasswordCredentialType = "username_password"
	passwordCredentialType         = "password"
	sshPrivateKeyCredentialType    = "ssh_private_key"
)

// UsernamePassword contains username and password credentials
type UsernamePassword struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`

	Raw *targets.SessionCredential
	// Consumed can be set by the caller to indicate that the credential has
	// been used, e.g. displayed to the user
	Consumed bool
}

// Password contains a password credential
type Password struct {
	Password string `mapstructure:"password"`

	Raw *targets.SessionCredential
	// Consumed can be set by the caller to indicate that the credential has
	// been used, e.g. displayed to the user
	Consumed bool
}

// SshPrivateKey contains the username and private key with optional passphrase
// for the key
type SshPrivateKey struct {
	Username   string `mapstructure:"username"`
	PrivateKey string `mapstructure:"private_key"`
	Passphrase string `mapstructure:"private_key_passphrase"`

	Raw *targets.SessionCredential
	// Consumed can be set by the caller to indicate that the credential has
	// been used, e.g. displayed to the user
	Consumed bool
}

type Credentials struct {
	UsernamePassword []UsernamePassword
	Password         []Password
	SshPrivateKey    []SshPrivateKey
	// Unspecified are credentials that do not match one of the types above
	Unspecified []*targets.SessionCredential
}

func (c Credentials) UnconsumedSessionCredentials() []*targets.SessionCredential {
	out := make([]*targets.SessionCredential, 0, len(c.SshPrivateKey)+len(c.UsernamePassword)+len(c.Unspecified))

	// Unspecified credentials cannot be consumed
	out = append(out, c.Unspecified...)

	for _, c := range c.SshPrivateKey {
		if !c.Consumed {
			out = append(out, c.Raw)
		}
	}
	for _, c := range c.UsernamePassword {
		if !c.Consumed {
			out = append(out, c.Raw)
		}
	}
	for _, c := range c.Password {
		if !c.Consumed {
			out = append(out, c.Raw)
		}
	}
	return out
}

func ParseCredentials(creds []*targets.SessionCredential) (Credentials, error) {
	if creds == nil {
		return Credentials{}, nil
	}
	var out Credentials
	for _, cred := range creds {
		if cred.CredentialSource == nil {
			return Credentials{}, errors.New("missing credential source")
		}

		var upCred UsernamePassword
		var pCred Password
		var spkCred SshPrivateKey
		switch cred.CredentialSource.CredentialType {
		case usernamePasswordCredentialType:
			// Decode attributes from credential struct
			if err := mapstructure.Decode(cred.Credential, &upCred); err != nil {
				return Credentials{}, err
			}

			if upCred.Username != "" && upCred.Password != "" {
				upCred.Raw = cred
				out.UsernamePassword = append(out.UsernamePassword, upCred)
				continue
			}

		case passwordCredentialType:
			// Decode attributes from credential struct
			if err := mapstructure.Decode(cred.Credential, &pCred); err != nil {
				return Credentials{}, err
			}

			if pCred.Password != "" {
				pCred.Raw = cred
				out.Password = append(out.Password, pCred)
				continue
			}

		case sshPrivateKeyCredentialType:
			// Decode attributes from credential struct
			if err := mapstructure.Decode(cred.Credential, &spkCred); err != nil {
				return Credentials{}, err
			}

			if spkCred.Username != "" && spkCred.PrivateKey != "" {
				spkCred.Raw = cred
				out.SshPrivateKey = append(out.SshPrivateKey, spkCred)
				continue
			}
		}

		// Credential type is unspecified, make a best effort attempt to parse
		// a credential from the Decoded field if it exists
		if cred.Secret != nil && cred.Secret.Decoded != nil {
			// Attempt unmarshaling into username password creds
			if err := mapstructure.Decode(cred.Secret.Decoded, &upCred); err != nil {
				return Credentials{}, err
			}
			if upCred.Username != "" && upCred.Password != "" {
				upCred.Raw = cred
				out.UsernamePassword = append(out.UsernamePassword, upCred)
				continue
			}

			// Attempt unmarshaling into password creds
			if err := mapstructure.Decode(cred.Secret.Decoded, &pCred); err != nil {
				return Credentials{}, err
			}
			if pCred.Password != "" {
				pCred.Raw = cred
				out.Password = append(out.Password, pCred)
				continue
			}

			// Attempt unmarshaling into ssh private key creds
			if err := mapstructure.Decode(cred.Secret.Decoded, &spkCred); err != nil {
				return Credentials{}, err
			}
			if spkCred.Username != "" && spkCred.PrivateKey != "" {
				spkCred.Raw = cred
				out.SshPrivateKey = append(out.SshPrivateKey, spkCred)
				continue
			}
		}

		// We could not parse the credential
		out.Unspecified = append(out.Unspecified, cred)
	}

	return out, nil
}
