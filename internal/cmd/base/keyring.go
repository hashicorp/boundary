// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/api/authtokens"
	nkeyring "github.com/jefferai/keyring"
	"github.com/mitchellh/cli"
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

// ErrNoToken is returned when no matching token could be found in the keyring
var ErrNoToken = errors.New("no token found")

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

// ReadTokenFromKeyring will attempt to read the token with the name tokenName from the keyring
// described by keyringType. It will return ErrNoToken if no token is found in the provided keyring.
func ReadTokenFromKeyring(ui cli.Ui, keyringType, tokenName string) (*authtokens.AuthToken, error) {
	const op = "base.ReadTokenFromKeyring"
	var token string
	var err error

	switch keyringType {
	case NoneKeyring:
		return nil, ErrNoToken

	case WincredKeyring, KeychainKeyring:
		token, err = zkeyring.Get(StoredTokenName, tokenName)
		if err != nil {
			if err == zkeyring.ErrNotFound {
				ui.Error("No saved credential found, continuing without")
			} else {
				ui.Warn("Token must be provided via BOUNDARY_TOKEN env var or -token flag. Reading the token can also be disabled via -keyring-type=none.")
				return nil, fmt.Errorf("%s: error reading auth token from keyring: %w", op, err)
			}
		}

	default:
		krConfig := nkeyring.Config{
			LibSecretCollectionName: LoginCollection,
			PassPrefix:              PassPrefix,
			AllowedBackends:         []nkeyring.BackendType{nkeyring.BackendType(keyringType)},
		}

		kr, err := nkeyring.Open(krConfig)
		if err != nil {
			ui.Warn("Token must be provided via BOUNDARY_TOKEN env var or -token flag. Reading the token can also be disabled via -keyring-type=none.")
			return nil, fmt.Errorf("%s: failed to open keyring: %w", op, err)
		}

		item, err := kr.Get(tokenName)
		if err != nil {
			ui.Warn("Token must be provided via BOUNDARY_TOKEN env var or -token flag. Reading the token can also be disabled via -keyring-type=none.")
			return nil, fmt.Errorf("%s: failed to get token from keyring: %w", op, err)
		}

		token = string(item.Data)
	}

	if token != "" {
		tokenBytes, err := base64.RawStdEncoding.DecodeString(token)
		switch {
		case err != nil:
			return nil, fmt.Errorf("error base64-unmarshaling stored token from system credential store: %w", err)
		case len(tokenBytes) == 0:
			return nil, errors.New("zero length token after decoding stored token from system credential store")
		default:
			var authToken authtokens.AuthToken
			if err := json.Unmarshal(tokenBytes, &authToken); err != nil {
				return nil, fmt.Errorf("error unmarshaling stored token information after reading from system credential store: %s", err)
			} else {
				return &authToken, nil
			}
		}
	}
	return nil, ErrNoToken
}

// ReadTokenFromKeyring will attempt to read the token with the name tokenName from the keyring
// described by keyringType. It will return ErrNoToken if no token is found in the provided keyring.
func (c *Command) ReadTokenFromKeyring(keyringType, tokenName string) (*authtokens.AuthToken, error) {
	return ReadTokenFromKeyring(c.UI, keyringType, tokenName)
}

func TokenIdFromToken(token string) (string, error) {
	split := strings.Split(token, "_")
	if len(split) < 3 {
		return "", errors.New("Unexpected stored token format")
	}
	return strings.Join(split[0:2], "_"), nil
}
