package authmethods

import (
	"fmt"
	"net/textproto"
	"strconv"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*PasswordCommand)(nil)
var _ cli.CommandAutocomplete = (*PasswordCommand)(nil)

type PasswordCommand struct {
	*base.Command

	Func string

	flagMinLoginNameLength string
	flagMinPasswordLength  string
}

func (c *PasswordCommand) Synopsis() string {
	return fmt.Sprintf("%s a password-type auth-method within Boundary", textproto.CanonicalMIMEHeaderKey(c.Func))
}

var passwordFlagsMap = map[string][]string{
	"create": {"scope-id", "name", "description"},
	"update": {"id", "name", "description", "version"},
}

func (c *PasswordCommand) Help() string {
	var info string
	switch c.Func {
	case "create":
		info = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods password create [options] [args]",
			"",
			"  Create a password-type auth-method. Example:",
			"",
			`    $ boundary auth-methods password create -name prodops -description "Password auth-method for ProdOps"`,
			"",
			"",
		})

	case "update":
		info = base.WrapForHelpText([]string{
			"Usage: boundary auth-methods password update [options] [args]",
			"",
			"  Update a password-type auth-method given its ID. Example:",
			"",
			`    $ boundary auth-methods password update -id ampw_1234567890 -name "devops" -description "Password auth-method for DevOps"`,
			"",
			"",
		})
	}
	return info + c.Flags().Help()
}

func (c *PasswordCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(passwordFlagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		common.PopulateCommonFlags(c.Command, f, "password-type auth-method", passwordFlagsMap[c.Func])
	}

	f := set.NewFlagSet("Password Auth-Method Options")
	addPasswordFlags(c, f)

	return set
}

func (c *PasswordCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *PasswordCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *PasswordCommand) Run(args []string) int {
	if c.Func == "" {
		return cli.RunResultHelp
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if strutil.StrListContains(passwordFlagsMap[c.Func], "id") && c.FlagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
		return 1
	}
	if strutil.StrListContains(passwordFlagsMap[c.Func], "scope-id") && c.FlagScopeId == "" {
		c.UI.Error("Scope ID must be passed in via -scope-id")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	var opts []authmethods.Option

	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, authmethods.DefaultName())
	default:
		opts = append(opts, authmethods.WithName(c.FlagName))
	}

	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, authmethods.DefaultDescription())
	default:
		opts = append(opts, authmethods.WithDescription(c.FlagDescription))
	}

	var attributes map[string]interface{}
	addAttribute := func(name string, value interface{}) {
		if attributes == nil {
			attributes = make(map[string]interface{})
		}
		attributes[name] = value
	}
	switch c.flagMinLoginNameLength {
	case "":
	case "null":
		addAttribute("min_login_name_length", nil)
	default:
		length, err := strconv.ParseUint(c.flagMinLoginNameLength, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagMinLoginNameLength, err))
			return 1
		}
		addAttribute("min_login_name_length", uint32(length))
	}

	switch c.flagMinPasswordLength {
	case "":
	case "null":
		addAttribute("min_password_length", nil)
	default:
		length, err := strconv.ParseUint(c.flagMinPasswordLength, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagMinPasswordLength, err))
			return 1
		}
		addAttribute("min_password_length", uint32(length))
	}

	if attributes != nil {
		opts = append(opts, authmethods.WithAttributes(attributes))
	}

	authmethodClient := authmethods.NewClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create":
		// These don't update so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, authmethods.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	}

	var result api.GenericResult
	var apiErr *api.Error

	switch c.Func {
	case "create":
		result, apiErr, err = authmethodClient.Create(c.Context, "password", c.FlagScopeId, opts...)
	case "update":
		result, apiErr, err = authmethodClient.Update(c.Context, c.FlagId, version, opts...)
	}

	plural := "password-type auth-method"
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
	}
	if apiErr != nil {
		c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, pretty.Sprint(apiErr)))
		return 1
	}

	method := result.GetItem().(*authmethods.AuthMethod)
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(generateAuthMethodTableOutput(method))
	case "json":
		b, err := base.JsonFormatter{}.Format(method)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}
