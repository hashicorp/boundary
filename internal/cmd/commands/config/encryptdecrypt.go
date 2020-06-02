package config

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*EncryptDecryptCommand)(nil)
var _ cli.CommandAutocomplete = (*EncryptDecryptCommand)(nil)

type EncryptDecryptCommand struct {
	*base.Command
	Encrypt bool

	flagOverwrite bool
	flagStrip     bool
}

func (c *EncryptDecryptCommand) Synopsis() string {
	dir := "Decrypts"
	if c.Encrypt {
		dir = "Encrypts"
	}
	return fmt.Sprintf("%s sensitive values in Vault's configuration file", dir)
}

func (c *EncryptDecryptCommand) Help() string {
	subCmd := "Decrypt"
	if c.Encrypt {
		subCmd = "Encrypt"
	}
	helpText := `
Usage: watchtower config %s [options] [args]
  
	%s sensitive values in a Watchtower's configuration file. These values must be marked
  with {{%s()}} as appropriate. This can only be used with string parameters, and
  the markers must be inside the quote marks delimiting the string; as an example:
    
		foo = "{{encrypt(bar)}}"
  
	By default this will print the new configuration out. To overwrite into the same
  file use the -overwrite flag.
    
		$ watchtower config %s -overwrite config.hcl
																																				`
	helpText = fmt.Sprintf(helpText, strings.ToLower(subCmd), subCmd, strings.ToLower(subCmd), strings.ToLower(subCmd))

	return strings.TrimSpace(helpText)
}

func (c *EncryptDecryptCommand) Flags() *base.FlagSets {
	set := c.FlagSet(0)

	f := set.NewFlagSet("Command Options")

	f.BoolVar(&base.BoolVar{
		Name:   "overwrite",
		Target: &c.flagOverwrite,
		Usage:  "Overwrite the existing file.",
	})

	f.BoolVar(&base.BoolVar{
		Name:   "strip",
		Target: &c.flagStrip,
		Usage:  "Strip the declarations from the file afterwards.",
	})

	return set
}

func (c *EncryptDecryptCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *EncryptDecryptCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *EncryptDecryptCommand) Run(args []string) (ret int) {
	op := "decrypt"
	if c.Encrypt {
		op = "encrypt"
	}

	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	path := ""
	args = f.Args()
	switch len(args) {
	case 1:
		path = strings.TrimSpace(args[0])
	default:
		c.UI.Error(fmt.Sprintf("Incorrect arguments (expected 1, got %d)", len(args)))
		return 1
	}

	if path == "" {
		c.UI.Error("A configuration file must be specified")
		return 1
	}

	kmses, err := configutil.LoadConfigKMSes(path)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error loading configuration from %s: %w", path, err).Error())
		return 1
	}

	var kms *configutil.KMS
	for _, v := range kmses {
		if strutil.StrListContains(v.Purpose, "config") {
			if kms != nil {
				c.UI.Error("Only one seal/kms block marked for \"config\" purpose is allowed")
				return 1
			}
			kms = v
		}
	}
	if kms == nil {
		c.UI.Error("No seal/kms block with \"config\" purpose defined in the configuration file")
		return 1
	}

	d, err := ioutil.ReadFile(path)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error reading config file: %w", err).Error())
		return 1
	}

	raw := string(d)

	wrapper, err := configutil.ConfigureWrapper(kms, nil, nil, nil)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error creating kms: %w", err).Error())
		return 1
	}

	wrapper.Init(context.Background())
	defer wrapper.Finalize(context.Background())

	raw, err = configutil.EncryptDecrypt(raw, !c.Encrypt, c.flagStrip, wrapper)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error %sing via kms: %w", op, err).Error())
		return 1
	}

	if !c.flagOverwrite {
		c.UI.Output(raw)
		return 0
	}

	file, err := os.Create(path)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error opening file for writing: %w", err).Error())
		return 1
	}

	defer func() {
		if err := file.Close(); err != nil {
			c.UI.Error(fmt.Errorf("Error closing file after writing: %w", err).Error())
			ret = 1
		}
	}()

	n, err := file.WriteString(raw)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error writing to file: %w", err).Error())
		return 1
	}
	if n != len(raw) {
		c.UI.Error(fmt.Sprintf("Wrong number of bytes written to file, expected %d, wrote %d", len(raw), n))
	}

	return 0
}
