package authmethods

import (
	"fmt"
	"net/textproto"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var _ cli.Command = (*PasswordCommand)(nil)
var _ cli.CommandAutocomplete = (*PasswordCommand)(nil)

type PasswordCommand struct {
	*base.Command

	Func     string
	flagType string
	flagsErr string

	// Password method flags
	flagPasswordMinLoginNameLength string
	flagPasswordMinPasswordLength  string
}

func (c *PasswordCommand) Synopsis() string {
	return fmt.Sprintf("%s a password-type auth-method within Boundary", textproto.CanonicalMIMEHeaderKey(c.Func))
}

var passwordFlagsMap = map[string][]string{
	"create": {"name", "description"},
	"update": {"id", "name", "description", "version"},
}

func (c *PasswordCommand) Help() string {
	switch c.Func {
	case "create":
		return base.WrapForHelpText([]string{
			"Usage: boundary auth-methods password create [options] [args]",
			"",
			"  Create a password-type auth-method. Example:",
			"",
			`    $ boundary auth-methods password create -name prodops -description "Password auth-method for ProdOps"`,
			"",
			"",
		})

	case "update":
		return base.WrapForHelpText([]string{
			"Usage: boundary auth-methods password update [options] [args]",
			"",
			"  Update a password-type auth-method given its ID. Example:",
			"",
			`    $ boundary auth-methods password update -id paum_1234567890 -name "devops" -description "Password auth-method for DevOps"`,
		})
	}
	return ""
}

func typeFlag(c *PasswordCommand, f *base.FlagSet) {
	f.StringVar(&base.StringVar{
		Name:    "type",
		EnvVar:  "BOUNDARY_AUTH_METHOD_TYPE",
		Target:  &c.flagType,
		Default: c.flagType,
		Usage:   "The type of auth method to create or update",
	})
}

func (c *PasswordCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	if len(passwordFlagsMap[c.Func]) > 0 {
		f := set.NewFlagSet("Command Options")
		common.PopulateCommonFlags(c.Command, f, resource.User, passwordFlagsMap[c.Func])
		if c.Func == "create" {
			typeFlag(c, f)
		}
	}

	if c.Func == "create" || c.Func == "update" {
		switch c.flagType {
		case "password":
			c.flagsErr = ""
			f := set.NewFlagSet("Password Auth Method Options")
			addTypeFlags(c, f, c.flagType)

		case "":
			c.flagsErr = ""
			// Do everything for the normal help output, but in sections
			for _, v := range []string{"Password"} {
				f := set.NewFlagSet(fmt.Sprintf("%s Auth Method Options", v))
				addTypeFlags(c, f, strings.ToLower(v))
			}

		default:
			c.flagsErr = fmt.Sprintf("Unknown auth method type %q", c.flagType)
		}
	}

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

	switch c.Func {
	case "update":
		// Do an initial parse so we can get a client for checking type
		f := c.Flags()
		if c.flagsErr != "" {
			c.UI.Error(c.flagsErr)
			return 1
		}

		if err := f.Parse(args); err != nil {
			c.UI.Error(err.Error())
			return 1
		}

		client, err := c.Client()
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
			return 2
		}

		// Attempt to discover the type
		am, _, _ := authmethods.NewAuthMethodsClient(client).Read(c.Context, c.FlagId)
		if am != nil {
			c.flagType = am.Type
		}

	case "create":
		// Discover type from the flag
		for i, v := range args {
			if v == "-type" {
				if i+1 >= len(args) {
					c.UI.Error("Missing argument for -type")
					return 1
				}
				c.flagType = args[i+1]
			}
		}
		if c.flagType == "" {
			c.flagType = os.Getenv("BOUNDARY_AUTH_METHOD_TYPE")
		}
	}

	f := c.Flags()
	if c.flagsErr != "" {
		c.UI.Error(c.flagsErr)
		return 1
	}

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	if c.Func == "create" && c.flagType == "" {
		c.UI.Error("Type is required but not passed in via -type")
		return 1
	}

	if strutil.StrListContains(passwordFlagsMap[c.Func], "id") && c.FlagId == "" {
		c.UI.Error("ID is required but not passed in via -id")
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}

	var opts []authmethods.Option

	if c.Func == "create" {
		opts = append(opts, authmethods.WithType(c.flagType))
	}

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
	if c.Func == "create" || c.Func == "update" {
		switch c.flagType {
		case "password":
			switch c.flagPasswordMinLoginNameLength {
			case "":
			case "null":
				if attributes == nil {
					attributes = make(map[string]interface{})
				}
				attributes["min_login_name_length"] = nil
			default:
				if attributes == nil {
					attributes = make(map[string]interface{})
				}
				attributes["min_login_name_length"] = c.flagPasswordMinLoginNameLength
			}

			switch c.flagPasswordMinPasswordLength {
			case "":
			case "null":
				if attributes == nil {
					attributes = make(map[string]interface{})
				}
				attributes["min_password_length"] = nil
			default:
				if attributes == nil {
					attributes = make(map[string]interface{})
				}
				attributes["min_password_length"] = c.flagPasswordMinPasswordLength
			}
		}
	}
	if attributes != nil {
		opts = append(opts, authmethods.WithAttributes(attributes))
	}

	authmethodClient := authmethods.NewAuthMethodsClient(client)

	// Perform check-and-set when needed
	var version uint32
	switch c.Func {
	case "create", "read", "delete", "list":
		// These don't udpate so don't need the existing version
	default:
		switch c.FlagVersion {
		case 0:
			opts = append(opts, authmethods.WithAutomaticVersioning())
		default:
			version = uint32(c.FlagVersion)
		}
	}

	var existed bool
	var method *authmethods.AuthMethod
	var listedMethods []*authmethods.AuthMethod
	var apiErr *api.Error

	switch c.Func {
	case "create":
		method, apiErr, err = authmethodClient.Create(c.Context, opts...)
	case "update":
		method, apiErr, err = authmethodClient.Update(c.Context, c.FlagId, version, opts...)
	case "read":
		method, apiErr, err = authmethodClient.Read(c.Context, c.FlagId, opts...)
	case "delete":
		existed, apiErr, err = authmethodClient.Delete(c.Context, c.FlagId, opts...)
	case "list":
		listedMethods, apiErr, err = authmethodClient.List(c.Context, opts...)
	}

	plural := "auth method"
	if c.Func == "list" {
		plural = "auth methods"
	}
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, plural, err.Error()))
		return 2
	}
	if apiErr != nil {
		c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, plural, pretty.Sprint(apiErr)))
		return 1
	}

	switch c.Func {
	case "delete":
		switch base.Format(c.UI) {
		case "json":
			c.UI.Output("null")
		case "table":
			output := "The delete operation completed successfully"
			switch existed {
			case true:
				output += "."
			default:
				output += ", however the resource did not exist at the time."
			}
			c.UI.Output(output)
		}
		return 0

	case "list":
		switch base.Format(c.UI) {
		case "json":
			if len(listedMethods) == 0 {
				c.UI.Output("null")
				return 0
			}
			b, err := base.JsonFormatter{}.Format(listedMethods)
			if err != nil {
				c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
				return 1
			}
			c.UI.Output(string(b))

		case "table":
			if len(listedMethods) == 0 {
				c.UI.Output("No auth methods found")
				return 0
			}
			var output []string
			output = []string{
				"",
				"Auth Method information:",
			}
			for i, m := range listedMethods {
				if i > 0 {
					output = append(output, "")
				}
				if true {
					output = append(output,
						fmt.Sprintf("  ID:             %s", m.Id),
						fmt.Sprintf("    Version:      %d", m.Version),
						fmt.Sprintf("    Type:         %s", m.Type),
					)
				}
				if m.Name != "" {
					output = append(output,
						fmt.Sprintf("    Name:         %s", m.Name),
					)
				}
				if m.Description != "" {
					output = append(output,
						fmt.Sprintf("    Description:  %s", m.Description),
					)
				}
			}
			c.UI.Output(base.WrapForHelpText(output))
		}
		return 0
	}

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
