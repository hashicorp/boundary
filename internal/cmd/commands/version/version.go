// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package version

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
	ver "github.com/hashicorp/boundary/version"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*Command)(nil)
	_ cli.CommandAutocomplete = (*Command)(nil)
)

type Command struct {
	*base.Command
}

func (c *Command) Synopsis() string {
	return "Print the version of the local Boundary binary"
}

func (c *Command) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary version",
		"",
		"  This command displays the version of the local Boundary binary.",
	}) + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetOutputFormat)

	return set
}

func (c *Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *Command) Run(args []string) int {
	verInfo := ver.Get()

	if base.Format(c.UI) == "json" {
		b, err := base.JsonFormatter{}.Format(verInfo)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return base.CommandApiError
		}
		c.UI.Output(string(b))
		return base.CommandSuccess
	}

	nonAttributeMap := map[string]any{}
	if verInfo.CgoEnabled {
		nonAttributeMap["Cgo Enabled"] = verInfo.CgoEnabled
	}
	if verInfo.Revision != "" {
		nonAttributeMap["Git Revision"] = verInfo.Revision
	}
	if verInfo.Version != "" {
		nonAttributeMap["Version Number"] = verInfo.VersionNumber()
	}
	if verInfo.VersionMetadata != "" {
		nonAttributeMap["Metadata"] = verInfo.VersionMetadata
	}
	if verInfo.BuildDate != "" {
		nonAttributeMap["Build Date"] = verInfo.BuildDate
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Version information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
	}

	c.UI.Output(base.WrapForHelpText(ret))

	return base.CommandSuccess
}
