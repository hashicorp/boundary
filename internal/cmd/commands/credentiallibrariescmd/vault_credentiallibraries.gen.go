// Code generated by "make cli"; DO NOT EDIT.
package credentiallibrariescmd

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/credentiallibraries"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

func initVaultFlags() {
	flagsOnce.Do(func() {
		extraFlags := extraVaultActionsFlagsMapFunc()
		for k, v := range extraFlags {
			flagsVaultMap[k] = append(flagsVaultMap[k], v...)
		}
	})
}

var (
	_ cli.Command             = (*VaultCommand)(nil)
	_ cli.CommandAutocomplete = (*VaultCommand)(nil)
)

type VaultCommand struct {
	*base.Command

	Func string

	plural string

	extraVaultCmdVars
}

func (c *VaultCommand) AutocompleteArgs() complete.Predictor {
	initVaultFlags()
	return complete.PredictAnything
}

func (c *VaultCommand) AutocompleteFlags() complete.Flags {
	initVaultFlags()
	return c.Flags().Completions()
}

func (c *VaultCommand) Synopsis() string {
	if extra := extraVaultSynopsisFunc(c); extra != "" {
		return extra
	}

	synopsisStr := "credential library"

	synopsisStr = fmt.Sprintf("%s %s", "vault-type", synopsisStr)

	return common.SynopsisFunc(c.Func, synopsisStr)
}

func (c *VaultCommand) Help() string {
	initVaultFlags()

	var helpStr string
	helpMap := common.HelpMap("credential library")

	switch c.Func {

	default:

		helpStr = c.extraVaultHelpFunc(helpMap)

	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flagsVaultMap = map[string][]string{

	"create": {"credential-store-id", "name", "description"},

	"update": {"id", "name", "description", "version"},
}

func (c *VaultCommand) Flags() *base.FlagSets {
	if len(flagsVaultMap[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "vault-type credential library", flagsVaultMap, c.Func)

	extraVaultFlagsFunc(c, set, f)

	return set
}

func (c *VaultCommand) Run(args []string) int {
	initVaultFlags()

	switch c.Func {
	case "":
		return cli.RunResultHelp

	}

	c.plural = "vault-type credential library"
	switch c.Func {
	case "list":
		c.plural = "vault-type credential librarys"
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	if strutil.StrListContains(flagsVaultMap[c.Func], "id") && c.FlagId == "" {
		c.PrintCliError(errors.New("ID is required but not passed in via -id"))
		return base.CommandUserError
	}

	var opts []credentiallibraries.Option

	if strutil.StrListContains(flagsVaultMap[c.Func], "credential-store-id") {
		switch c.Func {

		case "create":
			if c.FlagCredentialStoreId == "" {
				c.PrintCliError(errors.New("CredentialStore ID must be passed in via -credential-store-id or BOUNDARY_CREDENTIAL_STORE_ID"))
				return base.CommandUserError
			}

		}
	}

	client, err := c.Client()
	if c.WrapperCleanupFunc != nil {
		defer func() {
			if err := c.WrapperCleanupFunc(); err != nil {
				c.PrintCliError(fmt.Errorf("Error cleaning kms wrapper: %w", err))
			}
		}()
	}
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %w", err))
		return base.CommandCliError
	}
	credentiallibrariesClient := credentiallibraries.NewClient(client)

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, credentiallibraries.DefaultName())
	default:
		opts = append(opts, credentiallibraries.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, credentiallibraries.DefaultDescription())
	default:
		opts = append(opts, credentiallibraries.WithDescription(c.FlagDescription))
	}

	if c.FlagFilter != "" {
		opts = append(opts, credentiallibraries.WithFilter(c.FlagFilter))
	}

	var version uint32

	switch c.Func {

	case "update":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, credentiallibraries.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}

	}

	if ok := extraVaultFlagsHandlingFunc(c, f, &opts); !ok {
		return base.CommandUserError
	}

	var resp *api.Response
	var item *credentiallibraries.CredentialLibrary

	var createResult *credentiallibraries.CredentialLibraryCreateResult

	var updateResult *credentiallibraries.CredentialLibraryUpdateResult

	switch c.Func {

	case "create":
		createResult, err = credentiallibrariesClient.Create(c.Context, c.FlagCredentialStoreId, opts...)
		resp = createResult.GetResponse()
		item = createResult.GetItem()

	case "update":
		updateResult, err = credentiallibrariesClient.Update(c.Context, c.FlagId, version, opts...)
		resp = updateResult.GetResponse()
		item = updateResult.GetItem()

	}

	resp, item, err = executeExtraVaultActions(c, resp, item, err, credentiallibrariesClient, version, opts)

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			var opts []base.Option

			opts = append(opts, base.WithAttributeFieldPrefix("vault"))

			c.PrintApiError(apiErr, fmt.Sprintf("Error from controller when performing %s on %s", c.Func, c.plural), opts...)
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return base.CommandCliError
	}

	output, err := printCustomVaultActionOutput(c)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	if output {
		return base.CommandSuccess
	}

	switch c.Func {

	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(printItemTable(item, resp))

	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}

var (
	extraVaultActionsFlagsMapFunc = func() map[string][]string { return nil }
	extraVaultSynopsisFunc        = func(*VaultCommand) string { return "" }
	extraVaultFlagsFunc           = func(*VaultCommand, *base.FlagSets, *base.FlagSet) {}
	extraVaultFlagsHandlingFunc   = func(*VaultCommand, *base.FlagSets, *[]credentiallibraries.Option) bool { return true }
	executeExtraVaultActions      = func(_ *VaultCommand, inResp *api.Response, inItem *credentiallibraries.CredentialLibrary, inErr error, _ *credentiallibraries.Client, _ uint32, _ []credentiallibraries.Option) (*api.Response, *credentiallibraries.CredentialLibrary, error) {
		return inResp, inItem, inErr
	}
	printCustomVaultActionOutput = func(*VaultCommand) (bool, error) { return false, nil }
)
