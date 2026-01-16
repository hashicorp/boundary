// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"context"
	"errors"
	"fmt"
	"net/textproto"
	"os"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	kms_plugin_assets "github.com/hashicorp/boundary/plugins/kms"
	"github.com/hashicorp/boundary/sdk/wrapper"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	configutil "github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*EncryptDecryptCommand)(nil)
	_ cli.CommandAutocomplete = (*EncryptDecryptCommand)(nil)
)

type EncryptDecryptCommand struct {
	*base.Command
	Func string

	flagConfig    string
	flagConfigKms string
	flagOverwrite bool
	flagStrip     bool
}

func (c *EncryptDecryptCommand) Synopsis() string {
	return fmt.Sprintf("%s sensitive values in Boundary's configuration file", textproto.CanonicalMIMEHeaderKey(c.Func))
}

func (c *EncryptDecryptCommand) Help() string {
	var args []string
	args = append(args,
		"Usage: boundary config {{func}} [options] [args]",
		"",
		"  {{upperfunc}} sensitive values in a Boundary's configuration file. These values must be marked with {{{{func}}()}} as appropriate. Example:",
		"",
		`    foo = "{{encrypt(bar)}}"`,
		"",
		"  By default this will print out the new configuration. To overwrite into the same file use the -overwrite flag.",
		"",
		"    $ boundary config {{func}} -overwrite config.hcl",
		"",
		`  In order for this command to perform its task, a "kms" block must be defined within a configuration file. Example:`,
		"",
		`    kms "aead" {`,
		`      purpose = "config"`,
		`      aead_type = "aes-gcm"`,
		`      key = "7xtkEoS5EXPbgynwd+dDLHopaCqK8cq0Rpep4eooaTs="`,
		`    }`,
		"",
		`  The "kms" block can be defined in the configuration file or via the -config flag. If defined in the configuration file, only string parameters are supported, and the markers must be inside the quote marks delimiting the string. Additionally, if the block is defined inline, do NOT use an an "aead" block with the key defined in the configuration file as it provides no protection.`,
		"",
		"",
	)

	for i, line := range args {
		args[i] = strings.Replace(
			strings.Replace(
				line, "{{func}}", c.Func, -1,
			),
			"{{upperfunc}}", textproto.CanonicalMIMEHeaderKey(c.Func), -1,
		)
	}

	return base.WrapForHelpText(args) + c.Flags().Help()
}

func (c *EncryptDecryptCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetNone)

	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "config-kms",
		Target: &c.flagConfigKms,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
		),
		Usage: `If specified, the given file will be parsed for a "kms" block with purpose "config" and will use it to perform the command. If not set, the command will expect a block inline with the configuration file, and will only be able to support quoted string parameters.`,
	})

	f.StringVar(&base.StringVar{
		Name:   "config",
		Target: &c.flagConfig,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
		),
		Usage: `The configuration file upon which to perform encryption or decryption`,
	})

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
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	switch c.flagConfig {
	case "":
		c.UI.Error(`Missing required parameter -config`)
		return base.CommandUserError
	default:
		c.flagConfig = strings.TrimSpace(c.flagConfig)
	}

	kmsDefFile := c.flagConfig

	switch c.flagConfigKms {
	case "":
	default:
		kmsDefFile = strings.TrimSpace(c.flagConfigKms)
	}

	wrapper, cleanupFunc, err := wrapper.GetWrapperFromPath(
		c.Context,
		kmsDefFile,
		globals.KmsPurposeConfig,
		configutil.WithPluginOptions(
			pluginutil.WithPluginsMap(kms_plugin_assets.BuiltinKmsPlugins()),
			pluginutil.WithPluginsFilesystem(kms_plugin_assets.KmsPluginPrefix, kms_plugin_assets.FileSystem()),
		),
		// TODO: How would we want to expose this kind of log to users when
		// using recovery configs? Generally with normal CLI commands we
		// don't print out all of these logs. We may want a logger with a
		// custom writer behind our existing gate where we print nothing
		// unless there is an error, then dump all of it.
		configutil.WithLogger(hclog.NewNullLogger()),
	)
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	if wrapper == nil {
		c.UI.Error(`No wrapper with "config" purpose found"`)
		return base.CommandUserError
	}
	if cleanupFunc != nil {
		defer func() {
			if err := cleanupFunc(); err != nil {
				c.UI.Warn(fmt.Errorf("Error cleaning up KMS wrapper: %w", err).Error())
			}
		}()
	}

	if ifWrapper, ok := wrapper.(wrapping.InitFinalizer); ok {
		if err := ifWrapper.Init(c.Context); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
			c.UI.Error(fmt.Errorf("Error initializing KMS: %w", err).Error())
			return base.CommandUserError
		}
		defer func() {
			if err := ifWrapper.Finalize(context.Background()); err != nil && !errors.Is(err, wrapping.ErrFunctionNotImplemented) {
				c.UI.Warn(fmt.Errorf("Error encountered when finalizing KMS: %w", err).Error())
			}
		}()
	}

	d, err := os.ReadFile(c.flagConfig)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error reading config file: %w", err).Error())
		return base.CommandUserError
	}

	raw := string(d)

	raw, err = configutil.EncryptDecrypt(raw, c.Func == "decrypt", c.flagStrip, wrapper)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error %sing via kms: %w", c.Func, err).Error())
		return base.CommandCliError
	}

	if !c.flagOverwrite {
		c.UI.Output(raw)
		return base.CommandSuccess
	}

	file, err := os.Create(c.flagConfig)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error opening file for writing: %w", err).Error())
		return base.CommandCliError
	}

	defer func() {
		if err := file.Close(); err != nil {
			c.UI.Error(fmt.Errorf("Error closing file after writing: %w", err).Error())
			ret = base.CommandCliError
		}
	}()

	n, err := file.WriteString(raw)
	if err != nil {
		c.UI.Error(fmt.Errorf("Error writing to file: %w", err).Error())
		return base.CommandCliError
	}
	if n != len(raw) {
		c.UI.Error(fmt.Sprintf("Wrong number of bytes written to file, expected %d, wrote %d", len(raw), n))
	}

	return ret
}
