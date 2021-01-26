package targetscmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

type extraCmdVars = struct {
	flagHostSets []string
	flagHostId   string
	sar          *targets.SessionAuthorizationResult
}

var extraActionsFlagsMap = map[string][]string{
	"authorize-session": {"id", "host-id"},
	"add-host-sets":     {"id", "host-set", "version"},
	"remove-host-sets":  {"id", "host-set", "version"},
	"set-host-sets":     {"id", "host-set", "version"},
}

func (c *Command) extraSynopsisFunc() string {
	switch c.Func {
	case "add-host-sets", "set-host-sets", "remove-host-sets":
		var in string
		switch {
		case strings.HasPrefix(c.Func, "add"):
			in = "Add host sets to"
		case strings.HasPrefix(c.Func, "set"):
			in = "Set the full contents of the host sets on"
		case strings.HasPrefix(c.Func, "remove"):
			in = "Remove host sets from"
		}
		return wordwrap.WrapString(fmt.Sprintf("%s a target", in), base.TermWidth)

	case "authorize-session":
		return "Request session authorization against the target"

	default:
		return ""
	}
}

func (c *Command) extraFlagsFunc(f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case "host-set":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "host-set",
				Target: &c.flagHostSets,
				Usage:  "The host-set resources to add, remove, or set. May be specified multiple times.",
			})
		case "host-id":
			f.StringVar(&base.StringVar{
				Name:   "host-id",
				Target: &c.flagHostId,
				Usage:  "The ID of a specific host to connect to out of the hosts from the target's host sets. If not specified, one is chosen at random.",
			})
		}
	}

	if c.Func == "authorize-session" {
		flagsMap[c.Func] = append(flagsMap[c.Func], "name", "scope-id", "scope-name")

		// We put these here to change usage and change defaults (don't want
		// them populated by default). Otherwise the common flags function will
		// populate these values, and they can't be changed after-the-fact.
		f.StringVar(&base.StringVar{
			Name:   "name",
			Target: &c.FlagName,
			Usage:  "Target name, if authorizing the session via scope parameters and target name.",
		})

		f.StringVar(&base.StringVar{
			Name:       "scope-id",
			Target:     &c.FlagScopeId,
			EnvVar:     "BOUNDARY_SCOPE_ID",
			Completion: complete.PredictAnything,
			Usage:      "Target scope ID, if authorizing the session via scope parameters and target name. Mutually exclusive with -scope-name.",
		})

		f.StringVar(&base.StringVar{
			Name:       "scope-name",
			Target:     &c.FlagScopeName,
			EnvVar:     "BOUNDARY_SCOPE_NAME",
			Completion: complete.PredictAnything,
			Usage:      "Target scope name, if authorizing the session via scope parameters and target name. Mutually exclusive with -scope-id.",
		})
	}
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary targets [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary target resources. Example:",
			"",
			"    Read a target:",
			"",
			`      $ boundary targets read -id ttcp_1234567890`,
			"",
			"  Please see the targets subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary targets create [type] [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary target resources. Example:",
			"",
			"    Create a tcp-type target:",
			"",
			`      $ boundary targets create tcp -name prodops -description "For ProdOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary targets update [type] [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary target resources. Example:",
			"",
			"    Update a tcp-type target:",
			"",
			`      $ boundary targets update tcp -id ttcp_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the typed subcommand help for detailed usage information.",
		})
	case "add-host-sets":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target add-host-sets [options] [args]",
			"",
			"  This command allows adding host-set resources to target resources. Example:",
			"",
			"    Add host-set resources to a tcp-type target:",
			"",
			`      $ boundary targets add-host-sets -id ttcp_1234567890 -host-set hsst_1234567890 -host-set hsst_0987654321`,
			"",
			"",
		})
	case "remove-host-sets":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target remove-host-sets [options] [args]",
			"",
			"  This command allows removing host-set resources from target resources. Example:",
			"",
			"    Remove host-set resources from a tcp-type target:",
			"",
			`      $ boundary targets add-host-sets -id ttcp_1234567890 -host hsst_1234567890 -host-set hsst_0987654321`,
			"",
			"",
		})
	case "set-host-sets":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target set-host-sets [options] [args]",
			"",
			"  This command allows setting the complete set of host-set resources on a target resource. Example:",
			"",
			"    Set host-set resources on a tcp-type target:",
			"",
			`      $ boundary targets set-host-sets -id ttcp_1234567890 -host-set hsst_1234567890`,
			"",
			"",
		})
	case "authorize-session":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target authorize-session [options] [args]",
			"",
			"  This command allows fetching session authorization credentials against a target. Example:",
			"",
			"    Request an authorized session using the target ID:",
			"",
			`      $ boundary targets authorize-session -id ttcp_1234567890`,
			"",
			"    Request an authorized session using the scope ID and target name:",
			"",
			`      $ boundary targets authorize-session -scope-id o_1234567890 -name prod-ssh`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) extraFlagHandlingFunc(opts *[]targets.Option) int {
	// This is custom logic because of the authorized-session handling. If we
	// support all resources to be looked up by name + scope info we can
	// eventually graduate this out to the main template.
	if strutil.StrListContains(flagsMap[c.Func], "id") {
		switch c.Func {
		case "authorize-session":
			if c.FlagId == "" &&
				(c.FlagName == "" ||
					(c.FlagScopeId == "" && c.FlagScopeName == "")) {
				c.UI.Error("ID was not passed in, but no combination of name and scope ID/name was passed in either")
				return 1
			}
			if c.FlagId != "" &&
				(c.FlagName != "" || c.FlagScopeId != "" || c.FlagScopeName != "") {
				c.UI.Error("Cannot specify a target ID and also other lookup parameters")
				return 1
			}
		default:
			if c.FlagId == "" {
				c.UI.Error("ID is required but not passed in via -id")
				return 1
			}
		}
	}

	switch c.Func {
	case "add-host-sets", "remove-host-sets":
		if len(c.flagHostSets) == 0 {
			c.UI.Error("No host-sets supplied via -host-set")
			return 1
		}

	case "set-host-sets":
		switch len(c.flagHostSets) {
		case 0:
			c.UI.Error("No host-sets supplied via -host-set")
			return 1
		case 1:
			if c.flagHostSets[0] == "null" {
				c.flagHostSets = nil
			}
		}

	case "authorize-session":
		if len(c.flagHostId) != 0 {
			*opts = append(*opts, targets.WithHostId(c.flagHostId))
		}
	}

	return 0
}

func (c *Command) executeExtraActions(origResult api.GenericResult, origError error, targetClient *targets.Client, version uint32, opts []targets.Option) (api.GenericResult, error) {
	switch c.Func {
	case "add-host-sets":
		return targetClient.AddHostSets(c.Context, c.FlagId, version, c.flagHostSets, opts...)
	case "remove-host-sets":
		return targetClient.RemoveHostSets(c.Context, c.FlagId, version, c.flagHostSets, opts...)
	case "set-host-sets":
		return targetClient.SetHostSets(c.Context, c.FlagId, version, c.flagHostSets, opts...)
	case "authorize-session":
		var err error
		c.plural = "a session against target"
		c.sar, err = targetClient.AuthorizeSession(c.Context, c.FlagId, opts...)
		return nil, err
	}
	return origResult, origError
}

func (c *Command) printListTable(items []*targets.Target) string {
	if len(items) == 0 {
		return "No targets found"
	}
	var output []string
	output = []string{
		"",
		"Target information:",
	}
	for i, m := range items {
		if i > 0 {
			output = append(output, "")
		}
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", m.Id),
			)
		}
		if c.FlagRecursive {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", m.Scope.Id),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Version:             %d", m.Version),
				fmt.Sprintf("    Type:                %s", m.Type),
			)
		}
		if m.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                %s", m.Name),
			)
		}
		if m.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:         %s", m.Description),
			)
		}
		if len(m.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, m.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(item *targets.Target) string {
	nonAttributeMap := map[string]interface{}{
		"ID":                       item.Id,
		"Version":                  item.Version,
		"Type":                     item.Type,
		"Created Time":             item.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":             item.UpdatedTime.Local().Format(time.RFC1123),
		"Session Connection Limit": item.SessionConnectionLimit,
		"Session Max Seconds":      item.SessionMaxSeconds,
	}

	if item.Name != "" {
		nonAttributeMap["Name"] = item.Name
	}
	if item.Description != "" {
		nonAttributeMap["Description"] = item.Description
	}
	if item.WorkerFilter != "" {
		nonAttributeMap["Worker Filter"] = item.WorkerFilter
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	var hostSetMaps []map[string]interface{}
	if len(item.HostSets) > 0 {
		for _, set := range item.HostSets {
			m := map[string]interface{}{
				"ID":              set.Id,
				"Host Catalog ID": set.HostCatalogId,
			}
			hostSetMaps = append(hostSetMaps, m)
		}
		if l := len("Host Catalog ID"); l > maxLength {
			maxLength = l
		}
	}

	ret := []string{
		"",
		"Target information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(item.Scope, maxLength),
	}

	if len(item.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, item.AuthorizedActions),
		)
	}

	ret = append(ret,
		"",
	)

	if len(item.HostSets) > 0 {
		ret = append(ret,
			"  Host Sets:",
		)
		for _, m := range hostSetMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
				"",
			)
		}
	}

	if len(item.Attributes) > 0 {
		ret = append(ret,
			"  Attributes:",
			base.WrapMap(4, maxLength, item.Attributes),
		)
	}

	return base.WrapForHelpText(ret)
}

func (c *Command) printCustomActionOutput() (bool, error) {
	switch c.Func {
	case "authorize-session":
		item := c.sar.GetItem().(*targets.SessionAuthorization)

		switch base.Format(c.UI) {
		case "table":
			var ret []string

			nonAttributeMap := map[string]interface{}{
				"Session ID":          item.SessionId,
				"Target ID":           item.TargetId,
				"Scope ID":            item.Scope.Id,
				"User ID":             item.UserId,
				"Host ID":             item.HostId,
				"Endpoint":            item.Endpoint,
				"Created Time":        item.CreatedTime.Local().Format(time.RFC1123),
				"Type":                item.Type,
				"Authorization Token": item.AuthorizationToken,
			}

			maxLength := 0
			for k := range nonAttributeMap {
				if len(k) > maxLength {
					maxLength = len(k)
				}
			}

			ret = append(ret, "", "Target information:")
			ret = append(ret,
				// We do +2 because there is another +2 offset for host sets below
				base.WrapMap(2, maxLength+2, nonAttributeMap),
			)
			c.UI.Output(base.WrapForHelpText(ret))
			return true, nil

		case "json":
			b, err := base.JsonFormatter{}.Format(item)
			if err != nil {
				return false, fmt.Errorf("Error formatting as JSON: %w", err)
			}
			c.UI.Output(string(b))
			return true, nil
		}
	}

	return false, nil
}

var keySubstMap = map[string]string{
	"default_port": "Default Port",
}

func exampleOutput() string {
	in := &targets.Target{
		Id:      "ttcp_1234567890",
		ScopeId: "global",
		Scope: &scopes.ScopeInfo{
			Id: "global",
		},
		Name:        "foo",
		Description: "The bar of foos",
		CreatedTime: time.Now().Add(-5 * time.Minute),
		UpdatedTime: time.Now(),
		Version:     3,
		Type:        "tcp",
		HostSetIds:  []string{"hsst_1234567890", "hsst_0987654321"},
		HostSets: []*targets.HostSet{
			{
				Id:            "hsst_1234567890",
				HostCatalogId: "hcst_1234567890",
			},
			{
				Id:            "hsst_0987654321",
				HostCatalogId: "hcst_1234567890",
			},
		},
		Attributes: map[string]interface{}{
			"default_port": 22,
		},
	}
	return printItemTable(in)
}
