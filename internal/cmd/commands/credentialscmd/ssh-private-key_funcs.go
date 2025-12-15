// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialscmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api/credentials"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/password"
	"golang.org/x/crypto/ssh"
)

func init() {
	extraSshPrivateKeyFlagsFunc = extraSshPrivateKeyFlagsFuncImpl
	extraSshPrivateKeyActionsFlagsMapFunc = extraSshPrivateKeyActionsFlagsMapFuncImpl
	extraSshPrivateKeyFlagsHandlingFunc = extraSshPrivateKeyFlagHandlingFuncImpl
}

type extraSshPrivateKeyCmdVars struct {
	flagUsername             string
	flagPrivateKey           string
	flagPrivateKeyPassphrase string
}

func extraSshPrivateKeyActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			usernameFlagName,
			privateKeyFlagName,
			privateKeyPassphraseFlagName,
		},
	}
	flags["update"] = flags["create"]
	return flags
}

func extraSshPrivateKeyFlagsFuncImpl(c *SshPrivateKeyCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("SSH Private Key Credential Options")

	for _, name := range flagsSshPrivateKeyMap[c.Func] {
		switch name {
		case usernameFlagName:
			f.StringVar(&base.StringVar{
				Name:   usernameFlagName,
				Target: &c.flagUsername,
				Usage:  "The username associated with the credential.",
			})
		case privateKeyFlagName:
			f.StringVar(&base.StringVar{
				Name:   privateKeyFlagName,
				Target: &c.flagPrivateKey,
				Usage:  "The SSH private key associated with the credential. This can refer to a file on disk (file://) from which the value will be read or an env var (env://) from which the value will be read.",
			})
		case privateKeyPassphraseFlagName:
			f.StringVar(&base.StringVar{
				Name:   privateKeyPassphraseFlagName,
				Target: &c.flagPrivateKeyPassphrase,
				Usage:  "The passphrase associated with the SSH private key. This value is ignored if the private key does not require a passphrase or if no private key is supplied. This can refer to a file on disk (file://) from which the value will be read, or an env var (env://) from which the value will be read. Or, if left empty, if the key requires a passphrase it can be entered manually.",
			})
		}
	}
}

func extraSshPrivateKeyFlagHandlingFuncImpl(c *SshPrivateKeyCommand, _ *base.FlagSets, opts *[]credentials.Option) bool {
	switch c.flagUsername {
	case "":
	default:
		*opts = append(*opts, credentials.WithSshPrivateKeyCredentialUsername(c.flagUsername))
	}

	// If private key not set (e.g. just a username update) then don't check
	// either private key or passphrase
	if c.flagPrivateKey == "" {
		return true
	}

	// First parse private key
	privateKey, err := parseutil.MustParsePath(c.flagPrivateKey)
	switch {
	case err == nil:
	case errors.Is(err, parseutil.ErrNotAUrl), errors.Is(err, parseutil.ErrNotParsed):
		c.UI.Error("Private key flag must be used with env:// or file:// syntax")
		return false
	default:
		c.UI.Error(fmt.Sprintf("Error parsing private key flag: %v", err))
		return false
	}

	// Now validate it
	_, err = ssh.ParsePrivateKey([]byte(privateKey))

	// If nil, parsed successfully without passphrase, ignore passphrase flag
	if err == nil {
		if c.flagPrivateKeyPassphrase != "" {
			c.UI.Warn("Ignoring private key passphrase as private key is not encrypted.")
		}
		*opts = append(*opts, credentials.WithSshPrivateKeyCredentialPrivateKey(privateKey))
		return true
	}

	// If an error but it's not a passphrase missing error, send the error back
	if err.Error() != (&ssh.PassphraseMissingError{}).Error() {
		c.UI.Error(fmt.Sprintf("Error parsing private key: %v", err))
		return false
	}

	// Passphrase required
	var privateKeyPassphrase string
	switch c.flagPrivateKeyPassphrase {
	case "":
		fmt.Print("Please enter the passphrase for the private key (it will be hidden): ")
		privateKeyPassphrase, err = password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the passphrase. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return false
		}
		privateKeyPassphrase = strings.TrimSpace(privateKeyPassphrase)

	default:
		privateKeyPassphrase, err = parseutil.MustParsePath(c.flagPrivateKeyPassphrase)
		switch {
		case err == nil:
		case errors.Is(err, parseutil.ErrNotParsed):
			c.UI.Error("Private key passphrase flag must be used with env:// or file:// syntax")
			return false
		default:
			c.UI.Error(fmt.Sprintf("Error parsing private key passphrase flag: %v", err))
			return false
		}
	}

	if _, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(privateKeyPassphrase)); err != nil {
		c.UI.Error(fmt.Sprintf("Error parsing private key passphrase: %v", err))
		return false
	}

	*opts = append(*opts,
		credentials.WithSshPrivateKeyCredentialPrivateKey(privateKey),
		credentials.WithSshPrivateKeyCredentialPrivateKeyPassphrase(privateKeyPassphrase),
	)

	return true
}

func (c *SshPrivateKeyCommand) extraSshPrivateKeyHelpFunc(_ map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials create ssh-private-key -credential-store-id [options] [args]",
			"",
			"  Create an SSH private key credential. Example:",
			"",
			`    $ boundary credentials create ssh-private-key -credential-store-id csvlt_1234567890 -username user -private-key file:///home/user/.ssh/id_ed25519`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary credentials update ssh-private-key [options] [args]",
			"",
			"  Update an SSH private key credential given its ID. Example:",
			"",
			`    $ boundary credentials update ssh-private-key -id clvlt_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}
