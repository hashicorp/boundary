// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package base

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/api/authtokens"
	nkeyring "github.com/jefferai/keyring"
	"github.com/pkg/errors"
	zkeyring "github.com/zalando/go-keyring"
)

const (
	NoneKeyring          = "none"
	AutoKeyring          = "auto"
	WincredKeyring       = "wincred"
	PassKeyring          = "pass"
	KeychainKeyring      = "keychain"
	SecretServiceKeyring = "secret-service"

	DefaultTokenName = "default"
	LoginCollection  = "login"
	PassPrefix       = "HashiCorp_Boundary"
)

func (c *Command) DiscoverKeyringTokenInfo() (string, string, error) {
	// Stops the underlying library from invoking a dbus call that ends up
	// freezing some systems
	os.Setenv("DISABLE_KWALLET", "1")

	tokenName := DefaultTokenName

	if c.FlagTokenName != "" {
		tokenName = c.FlagTokenName
	}

	if tokenName == NoneKeyring {
		c.UI.Warn(`"-token-name=none" is deprecated, please use "-keyring-type=none"`)
		c.FlagKeyringType = NoneKeyring
	}

	if c.FlagKeyringType == NoneKeyring {
		return "", "", nil
	}

	// Set so we can look it up later when printing out curl strings
	os.Setenv(EnvTokenName, tokenName)

	var foundKeyringType bool
	keyringType := c.FlagKeyringType
	switch runtime.GOOS {
	case "windows":
		switch keyringType {
		case AutoKeyring, WincredKeyring, PassKeyring:
			foundKeyringType = true
			if keyringType == AutoKeyring {
				keyringType = WincredKeyring
			}
		}
	case "darwin":
		switch keyringType {
		case AutoKeyring, KeychainKeyring, PassKeyring:
			foundKeyringType = true
			if keyringType == AutoKeyring {
				keyringType = KeychainKeyring
			}
		}
	default:
		switch keyringType {
		case AutoKeyring, SecretServiceKeyring, PassKeyring:
			foundKeyringType = true
			if keyringType == AutoKeyring {
				keyringType = PassKeyring
			}
		}
	}

	if !foundKeyringType {
		return "", "", fmt.Errorf("Given keyring type %q is not valid, or not valid for this platform", c.FlagKeyringType)
	}

	var available bool
	switch keyringType {
	case WincredKeyring, KeychainKeyring:
		available = true
	case PassKeyring, SecretServiceKeyring:
		avail := nkeyring.AvailableBackends()
		for _, a := range avail {
			if keyringType == string(a) {
				available = true
			}
		}
	}

	if !available {
		return "", "", fmt.Errorf("Keyring type %q is not available on this machine. For help with setting up keyrings, see https://www.boundaryproject.io/docs/api-clients/cli.", keyringType)
	}

	os.Setenv(EnvKeyringType, keyringType)

	return keyringType, tokenName, nil
}

func (c *Command) ReadTokenFromKeyring(keyringType, tokenName string) *authtokens.AuthToken {
	var token string
	var err error

	switch keyringType {
	case NoneKeyring:
		return nil

	case WincredKeyring, KeychainKeyring:
		token, err = zkeyring.Get(StoredTokenName, tokenName)
		if err != nil {
			if err == zkeyring.ErrNotFound {
				c.UI.Error("No saved credential found, continuing without")
			} else {
				c.UI.Error(fmt.Sprintf("Error reading auth token from keyring: %s", err))
				c.UI.Warn("Token must be provided via BOUNDARY_TOKEN env var or -token flag. Reading the token can also be disabled via -keyring-type=none.")
			}
			token = ""
		}

	default:
		krConfig := nkeyring.Config{
			LibSecretCollectionName: LoginCollection,
			PassPrefix:              PassPrefix,
			AllowedBackends:         []nkeyring.BackendType{nkeyring.BackendType(keyringType)},
		}

		kr, err := nkeyring.Open(krConfig)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error opening keyring: %s", err))
			c.UI.Warn("Token must be provided via BOUNDARY_TOKEN env var or -token flag. Reading the token can also be disabled via -keyring-type=none.")
			break
		}

		item, err := kr.Get(tokenName)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error fetching token from keyring: %s", err))
			c.UI.Warn("Token must be provided via BOUNDARY_TOKEN env var or -token flag. Reading the token can also be disabled via -keyring-type=none.")
			break
		}

		token = string(item.Data)
	}

	if token != "" {
		tokenBytes, err := base64.RawStdEncoding.DecodeString(token)
		switch {
		case err != nil:
			c.UI.Error(fmt.Errorf("Error base64-unmarshaling stored token from system credential store: %w", err).Error())
		case len(tokenBytes) == 0:
			c.UI.Error("Zero length token after decoding stored token from system credential store")
		default:
			var authToken authtokens.AuthToken
			if err := json.Unmarshal(tokenBytes, &authToken); err != nil {
				c.UI.Error(fmt.Sprintf("Error unmarshaling stored token information after reading from system credential store: %s", err))
			} else {
				return &authToken
			}
		}
	}
	return nil
}

func (c *Command) SaveTokenToKeyring(token *authtokens.AuthToken) {
	var gotErr bool
	keyringType, tokenName, err := c.DiscoverKeyringTokenInfo()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error fetching keyring information: %s", err))
		gotErr = true
	} else if keyringType != "none" &&
		tokenName != "none" &&
		keyringType != "" &&
		tokenName != "" {
		marshaled, err := json.Marshal(token)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error marshaling auth token to save to keyring: %s", err))
			gotErr = true
		} else {
			switch keyringType {
			case "wincred", "keychain":
				if err := zkeyring.Set(StoredTokenName, tokenName, base64.RawStdEncoding.EncodeToString(marshaled)); err != nil {
					c.UI.Error(fmt.Sprintf("Error saving auth token to %q keyring: %s", keyringType, err))
					gotErr = true
				}

			default:
				krConfig := nkeyring.Config{
					LibSecretCollectionName: "login",
					PassPrefix:              "HashiCorp_Boundary",
					AllowedBackends:         []nkeyring.BackendType{nkeyring.BackendType(keyringType)},
				}

				kr, err := nkeyring.Open(krConfig)
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error opening %q keyring: %s", keyringType, err))
					gotErr = true
					break
				}

				if err := kr.Set(nkeyring.Item{
					Key:  tokenName,
					Data: []byte(base64.RawStdEncoding.EncodeToString(marshaled)),
				}); err != nil {
					c.UI.Error(fmt.Sprintf("Error storing token in %q keyring: %s", keyringType, err))
					gotErr = true
					break
				}
			}

			if !gotErr {
				c.UI.Output("\nThe token was successfully stored in the chosen keyring and is not displayed here.")
			}
		}
	}
	if gotErr {
		c.UI.Warn(fmt.Sprintf("The token was not successfully saved to a system keyring. The token is:\n\n%s\n\nIt must be manually passed in via the BOUNDARY_TOKEN env var or -token flag. Storing the token can also be disabled via -keyring-type=none.", token.Token))
	}
}

func TokenIdFromToken(token string) (string, error) {
	split := strings.Split(token, "_")
	if len(split) < 3 {
		return "", errors.New("Unexpected stored token format")
	}
	return strings.Join(split[0:2], "_"), nil
}
