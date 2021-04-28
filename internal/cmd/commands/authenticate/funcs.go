package authenticate

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	nkeyring "github.com/jefferai/keyring"
	zkeyring "github.com/zalando/go-keyring"
)

func saveAndOrPrintToken(c *base.Command, result *authmethods.AuthenticateResult) int {
	token := new(authtokens.AuthToken)
	if err := json.Unmarshal(result.GetRawAttributes(), token); err != nil {
		c.PrintCliError(fmt.Errorf("Error trying to decode response as an auth token: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(base.WrapForHelpText([]string{
			"",
			"Authentication information:",
			fmt.Sprintf("  Account ID:      %s", token.AccountId),
			fmt.Sprintf("  Auth Method ID:  %s", token.AuthMethodId),
			fmt.Sprintf("  Expiration Time: %s", token.ExpirationTime.Local().Format(time.RFC1123)),
			fmt.Sprintf("  User ID:         %s", token.UserId),
		}))

	case "json":
		if ok := c.PrintJsonItem(&dummyGenericResponse{
			item:     token,
			response: result.GetResponse(),
		}); !ok {
			return base.CommandCliError
		}
		return base.CommandSuccess
	}

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
				if err := zkeyring.Set(base.StoredTokenName, tokenName, base64.RawStdEncoding.EncodeToString(marshaled)); err != nil {
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

	switch {
	case gotErr:
		c.UI.Warn(fmt.Sprintf("The token was not successfully saved to a system keyring. The token is:\n\n%s\n\nIt must be manually passed in via the BOUNDARY_TOKEN env var or -token flag. Storing the token can also be disabled via -keyring-type=none.", token.Token))
	case c.FlagKeyringType == "none":
		c.UI.Warn("\nStoring the token in a keyring was disabled. The token is:")
		c.UI.Output(token.Token)
		c.UI.Warn("Please be sure to store it safely!")
	}

	return base.CommandSuccess
}
