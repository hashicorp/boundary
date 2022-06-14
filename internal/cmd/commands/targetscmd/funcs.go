package targetscmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraSynopsisFunc = extraSynopsisFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
	printCustomActionOutput = printCustomActionOutputImpl
}

type extraCmdVars struct {
	flagHostSets                     []string
	flagHostSources                  []string
	flagApplicationCredentialSources []string
	flagEgressCredentialSources      []string
	flagHostId                       string
	sar                              *targets.SessionAuthorizationResult
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"authorize-session":         {"id", "host-id"},
		"add-host-sets":             {"id", "host-set", "version"},
		"remove-host-sets":          {"id", "host-set", "version"},
		"set-host-sets":             {"id", "host-set", "version"},
		"add-host-sources":          {"id", "host-source", "version"},
		"remove-host-sources":       {"id", "host-source", "version"},
		"set-host-sources":          {"id", "host-source", "version"},
		"add-credential-sources":    {"id", "application-credential-source", "egress-credential-source", "version"},
		"remove-credential-sources": {"id", "application-credential-source", "egress-credential-source", "version"},
		"set-credential-sources":    {"id", "application-credential-source", "egress-credential-source", "version"},
	}
}

func extraSynopsisFuncImpl(c *Command) string {
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

	case "add-host-sources", "set-host-sources", "remove-host-sources":
		var in string
		switch {
		case strings.HasPrefix(c.Func, "add"):
			in = "Add host sources to"
		case strings.HasPrefix(c.Func, "set"):
			in = "Set the full contents of the host sources on"
		case strings.HasPrefix(c.Func, "remove"):
			in = "Remove host sources from"
		}
		return wordwrap.WrapString(fmt.Sprintf("%s a target", in), base.TermWidth)

	case "add-credential-sources", "set-credential-sources", "remove-credential-sources":
		var in string
		switch {
		case strings.HasPrefix(c.Func, "add"):
			in = "Add credential sources to"
		case strings.HasPrefix(c.Func, "set"):
			in = "Set the full contents of the credential sources on"
		case strings.HasPrefix(c.Func, "remove"):
			in = "Remove credential sources from"
		}
		return wordwrap.WrapString(fmt.Sprintf("%s a target", in), base.TermWidth)

	case "authorize-session":
		return "Request session authorization against the target"

	default:
		return ""
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
			"  DEPRECATED: Use add-host-sources instead.",
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
			"  DEPRECATED: Use remove-host-sources instead.",
			"",
			"  This command allows removing host-set resources from target resources. Example:",
			"",
			"    Remove host-set resources from a tcp-type target:",
			"",
			`      $ boundary targets remove-host-sets -id ttcp_1234567890 -host hsst_1234567890 -host-set hsst_0987654321`,
			"",
			"",
		})
	case "set-host-sets":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target set-host-sets [options] [args]",
			"",
			"  DEPRECATED: Use set-host-sources instead.",
			"",
			"  This command allows setting the complete set of host-set resources on a target resource. Example:",
			"",
			"    Set host-set resources on a tcp-type target:",
			"",
			`      $ boundary targets set-host-sets -id ttcp_1234567890 -host-set hsst_1234567890`,
			"",
			"",
		})
	case "add-host-sources":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target add-host-sources [options] [args]",
			"",
			"  This command allows adding host sources to target resources. Example:",
			"",
			"    Add host sources to a tcp-type target:",
			"",
			`      $ boundary targets add-host-sources -id ttcp_1234567890 -host-source hsst_1234567890 -host-source hsst_0987654321`,
			"",
			"",
		})
	case "remove-host-sources":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target remove-host-sources [options] [args]",
			"",
			"  This command allows removing host sources from target resources. Example:",
			"",
			"    Remove host sources from a tcp-type target:",
			"",
			`      $ boundary targets remove-host-sources -id ttcp_1234567890 -host-source hsst_1234567890 -host-source hsst_0987654321`,
			"",
			"",
		})
	case "set-host-sources":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target set-host-sources [options] [args]",
			"",
			"  This command allows setting the complete set of host sources on a target resource. Example:",
			"",
			"    Set host sources on a tcp-type target:",
			"",
			`      $ boundary targets set-host-sources -id ttcp_1234567890 -host-source hsst_1234567890`,
			"",
			"",
		})
	case "add-credential-sources":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target add-credential-sources [options] [args]",
			"",
			"  This command allows adding credential sources to target resources. Example:",
			"",
			"    Add credential sources to a tcp-type target:",
			"",
			`      $ boundary targets add-credential-sources -id ttcp_1234567890 -application-credential-source clvlt_1234567890 -application-credential-source clvlt_0987654321`,
			"",
			"",
		})
	case "remove-credential-sources":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target remove-credential-sources [options] [args]",
			"",
			"  This command allows removing credential sources from target resources. Example:",
			"",
			"    Remove credential sources from a tcp-type target:",
			"",
			`      $ boundary targets remove-credential-sources -id ttcp_1234567890 -application-credential-source clvlt_1234567890 -application-credential-source clvlt_0987654321`,
			"",
			"",
		})
	case "set-credential-sources":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary target set-credential-sources [options] [args]",
			"",
			"  This command allows setting the complete set of credential sources on a target resource. Example:",
			"",
			"    Set credential sources on a tcp-type target:",
			"",
			`      $ boundary targets set-credential-sources -id ttcp_1234567890 -application-credential-source clvlt_1234567890`,
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

func extraFlagsFuncImpl(c *Command, _ *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case "host-set":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "host-set",
				Target: &c.flagHostSets,
				Usage:  "The host-set resources to add, remove, or set. May be specified multiple times.",
			})
		case "host-source":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "host-source",
				Target: &c.flagHostSources,
				Usage:  "The host sources to add, remove, or set. May be specified multiple times.",
			})
		case "host-id":
			f.StringVar(&base.StringVar{
				Name:   "host-id",
				Target: &c.flagHostId,
				Usage:  "The ID of a specific host to connect to out of the hosts from the target's host sets. If not specified, one is chosen at random.",
			})
		case "application-credential-source":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "application-credential-source",
				Target: &c.flagApplicationCredentialSources,
				Usage:  "The credential source for application purpose to add, set, or remove.  May be specified multiple times.",
			})
		case "egress-credential-source":
			f.StringSliceVar(&base.StringSliceVar{
				Name:   "egress-credential-source",
				Target: &c.flagEgressCredentialSources,
				Usage:  "The credential source for egress purpose to add, set, or remove.  May be specified multiple times.",
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

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]targets.Option) bool {
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
				return false
			}
			if c.FlagId != "" &&
				(c.FlagName != "" || c.FlagScopeId != "" || c.FlagScopeName != "") {
				c.UI.Error("Cannot specify a target ID and also other lookup parameters")
				return false
			}
		default:
			if c.FlagId == "" {
				c.UI.Error("ID is required but not passed in via -id")
				return false
			}
		}
	}

	if strutil.StrListContains(flagsMap[c.Func], "scope-id") && c.FlagScopeId != "" {
		*opts = append(*opts, targets.WithScopeId(c.FlagScopeId))
	}

	switch c.Func {
	case "add-host-sets", "remove-host-sets":
		if len(c.flagHostSets) == 0 {
			c.UI.Error("No host-sets supplied via -host-set")
			return false
		}

	case "add-host-sources", "remove-host-sources":
		if len(c.flagHostSources) == 0 {
			c.UI.Error("No host sources supplied via -host-source")
			return false
		}

	case "set-host-sets":
		switch len(c.flagHostSets) {
		case 0:
			c.UI.Error("No host-sets supplied via -host-set")
			return false
		case 1:
			if c.flagHostSets[0] == "null" {
				c.flagHostSets = nil
			}
		}

	case "set-host-sources":
		switch len(c.flagHostSources) {
		case 0:
			c.UI.Error("No host sources supplied via -host-source")
			return false
		case 1:
			if c.flagHostSources[0] == "null" {
				c.flagHostSources = nil
			}
		}

	case "add-credential-sources", "remove-credential-sources":
		// TODO: As we add other purposes, add them to this check
		if len(c.flagApplicationCredentialSources)+len(c.flagEgressCredentialSources) == 0 {
			c.UI.Error("No credential sources supplied via -application-credential-source or -egress-credential-source")
			return false
		}

		if len(c.flagApplicationCredentialSources) > 0 {
			*opts = append(*opts, targets.WithApplicationCredentialSourceIds(c.flagApplicationCredentialSources))
		}
		if len(c.flagEgressCredentialSources) > 0 {
			*opts = append(*opts, targets.WithEgressCredentialSourceIds(c.flagEgressCredentialSources))
		}

	case "set-credential-sources":
		// TODO: As we add other purposes, add them to this check
		if len(c.flagApplicationCredentialSources)+len(c.flagEgressCredentialSources) == 0 {
			c.UI.Error("No credential sources supplied via -application-credential-source or -egress-credential-source")
			return false
		}

		switch len(c.flagApplicationCredentialSources) {
		case 0:
			// do nothing
		case 1:
			if c.flagApplicationCredentialSources[0] == "null" {
				*opts = append(*opts, targets.DefaultApplicationCredentialSourceIds())
				break
			}
			fallthrough
		default:
			*opts = append(*opts, targets.WithApplicationCredentialSourceIds(c.flagApplicationCredentialSources))
		}
		switch len(c.flagEgressCredentialSources) {
		case 0:
			// do nothing
		case 1:
			if c.flagEgressCredentialSources[0] == "null" {
				*opts = append(*opts, targets.DefaultEgressCredentialSourceIds())
				break
			}
			fallthrough
		default:
			*opts = append(*opts, targets.WithEgressCredentialSourceIds(c.flagEgressCredentialSources))
		}

	case "authorize-session":
		if len(c.flagHostId) != 0 {
			*opts = append(*opts, targets.WithHostId(c.flagHostId))
		}
	}

	return true
}

func executeExtraActionsImpl(c *Command, origResult api.GenericResult, origError error, targetClient *targets.Client, version uint32, opts []targets.Option) (api.GenericResult, error) {
	switch c.Func {
	case "add-host-sets":
		return targetClient.AddHostSets(c.Context, c.FlagId, version, c.flagHostSets, opts...)
	case "remove-host-sets":
		return targetClient.RemoveHostSets(c.Context, c.FlagId, version, c.flagHostSets, opts...)
	case "set-host-sets":
		return targetClient.SetHostSets(c.Context, c.FlagId, version, c.flagHostSets, opts...)
	case "add-host-sources":
		return targetClient.AddHostSources(c.Context, c.FlagId, version, c.flagHostSources, opts...)
	case "remove-host-sources":
		return targetClient.RemoveHostSources(c.Context, c.FlagId, version, c.flagHostSources, opts...)
	case "set-host-sources":
		return targetClient.SetHostSources(c.Context, c.FlagId, version, c.flagHostSources, opts...)
	case "add-credential-sources":
		return targetClient.AddCredentialSources(c.Context, c.FlagId, version, opts...)
	case "remove-credential-sources":
		return targetClient.RemoveCredentialSources(c.Context, c.FlagId, version, opts...)
	case "set-credential-sources":
		return targetClient.SetCredentialSources(c.Context, c.FlagId, version, opts...)
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
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", "(not available)"),
			)
		}
		if c.FlagRecursive && item.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.ScopeId),
			)
		}
		if item.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:             %d", item.Version),
			)
		}
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:                %s", item.Type),
			)
		}
		if item.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                %s", item.Name),
			)
		}
		if item.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:         %s", item.Description),
			)
		}
		if len(item.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, item.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(result api.GenericResult) string {
	item := result.GetItem().(*targets.Target)
	nonAttributeMap := map[string]interface{}{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Version != 0 {
		nonAttributeMap["Version"] = item.Version
	}
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
	}
	if !item.CreatedTime.IsZero() {
		nonAttributeMap["Created Time"] = item.CreatedTime.Local().Format(time.RFC1123)
	}
	if !item.UpdatedTime.IsZero() {
		nonAttributeMap["Updated Time"] = item.UpdatedTime.Local().Format(time.RFC1123)
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
	if result.GetResponse() != nil && result.GetResponse().Map != nil {
		if result.GetResponse().Map[globals.SessionConnectionLimitField] != nil {
			nonAttributeMap["Session Connection Limit"] = item.SessionConnectionLimit
		}
		if result.GetResponse().Map[globals.SessionMaxSecondsField] != nil {
			nonAttributeMap["Session Max Seconds"] = item.SessionMaxSeconds
		}
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	var hostSourceMaps []map[string]interface{}
	switch {
	case len(item.HostSources) > 0:
		for _, set := range item.HostSources {
			m := map[string]interface{}{
				"ID":              set.Id,
				"Host Catalog ID": set.HostCatalogId,
			}
			hostSourceMaps = append(hostSourceMaps, m)
		}
		if l := len("Host Catalog ID"); l > maxLength {
			maxLength = l
		}
	case len(item.HostSets) > 0:
		for _, set := range item.HostSets {
			m := map[string]interface{}{
				"ID":              set.Id,
				"Host Catalog ID": set.HostCatalogId,
			}
			hostSourceMaps = append(hostSourceMaps, m)
		}
		if l := len("Host Catalog ID"); l > maxLength {
			maxLength = l
		}
	}

	var credentialSourceMaps map[credential.Purpose][]map[string]interface{}
	if len(item.ApplicationCredentialSources) > 0 {
		if credentialSourceMaps == nil {
			credentialSourceMaps = make(map[credential.Purpose][]map[string]interface{})
		}
		var applicationCredentialSourceMaps []map[string]interface{}
		for _, source := range item.ApplicationCredentialSources {
			m := map[string]interface{}{
				"ID":                  source.Id,
				"Credential Store ID": source.CredentialStoreId,
			}
			applicationCredentialSourceMaps = append(applicationCredentialSourceMaps, m)
		}
		credentialSourceMaps[credential.ApplicationPurpose] = applicationCredentialSourceMaps
		if l := len("Credential Store ID"); l > maxLength {
			maxLength = l
		}
	}
	if len(item.EgressCredentialSources) > 0 {
		if credentialSourceMaps == nil {
			credentialSourceMaps = make(map[credential.Purpose][]map[string]interface{})
		}
		var egressCredentialSourceMaps []map[string]interface{}
		for _, source := range item.EgressCredentialSources {
			m := map[string]interface{}{
				"ID":                  source.Id,
				"Credential Store ID": source.CredentialStoreId,
			}
			egressCredentialSourceMaps = append(egressCredentialSourceMaps, m)
		}
		credentialSourceMaps[credential.EgressPurpose] = egressCredentialSourceMaps
		if l := len("Credential Store ID"); l > maxLength {
			maxLength = l
		}
	}

	ret := []string{
		"",
		"Target information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope:",
			base.ScopeInfoForOutput(item.Scope, maxLength),
		)
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

	if len(hostSourceMaps) > 0 {
		ret = append(ret,
			"  Host Sources:",
		)
		for _, m := range hostSourceMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
				"",
			)
		}
	}

	for purpose, sources := range credentialSourceMaps {
		switch purpose {
		case credential.ApplicationPurpose:
			ret = append(ret,
				"  Application Credential Sources:",
			)
		case credential.EgressPurpose:
			ret = append(ret,
				"  Egress Credential Sources:",
			)
		}
		for _, m := range sources {
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

func printCustomActionOutputImpl(c *Command) (bool, error) {
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
				// We do +2 because there is another +2 offset for credentials below
				base.WrapMap(2, maxLength+2, nonAttributeMap),
			)

			ret = append(ret,
				"",
			)
			if len(item.Credentials) > 0 {
				ret = append(ret,
					"  Credentials:",
				)

				for _, cred := range item.Credentials {
					if cred.Secret == nil || len(cred.Secret.Raw) == 0 {
						continue
					}

					ret = append(ret,
						fmt.Sprintf("    Credential Store ID:           %s", cred.CredentialSource.CredentialStoreId),
						fmt.Sprintf("    Credential Source ID:          %s", cred.CredentialSource.Id),
						fmt.Sprintf("    Credential Source Type:        %s", cred.CredentialSource.Type))

					if len(cred.CredentialSource.Name) > 0 {
						ret = append(ret,
							fmt.Sprintf("    Credential Source Name:        %s", cred.CredentialSource.Name))
					}
					if len(cred.CredentialSource.Description) > 0 {
						ret = append(ret,
							fmt.Sprintf("    Credential Source Description: %s", cred.CredentialSource.Description))
					}
					if cred.CredentialSource.CredentialType != "" {
						ret = append(ret,
							fmt.Sprintf("    Credential Type:               %s", cred.CredentialSource.CredentialType))
					}

					var secretStr []string
					switch cred.CredentialSource.Type {
					case "vault", "static":
						switch {
						case cred.Credential != nil:
							maxLength := 0
							for k := range cred.Credential {
								if len(k) > maxLength {
									maxLength = len(k)
								}
							}
							secretStr = []string{fmt.Sprintf("    %s", base.WrapMap(2, maxLength+2, cred.Credential))}

						default:
							// If it's Vault, the result will be JSON, except in
							// specific circumstances that aren't used for
							// credential fetching. So we can take the bytes
							// as-is (after base64-decoding), but we'll format
							// it nicely.
							in, err := base64.StdEncoding.DecodeString(strings.Trim(string(cred.Secret.Raw), `"`))
							if err != nil {
								return false, fmt.Errorf("Error decoding secret as base64: %w", err)
							}
							dst := new(bytes.Buffer)
							if err := json.Indent(dst, in, "      ", "  "); err != nil {
								return false, fmt.Errorf("Error pretty-printing JSON: %w", err)
							}
							secretStr = strings.Split(dst.String(), "\n")
							if len(secretStr) > 0 {
								// Indent doesn't apply to the first line 🙄
								secretStr[0] = fmt.Sprintf("      %s", secretStr[0])
							}
						}
					default:
						// If it's not Vault, and not another known type,
						// print out the base64-encoded value and leave it
						// to the user to sort out.
						secretStr = []string{fmt.Sprintf("      %s", secretStr)}
					}
					ret = append(ret, "    Secret:")
					ret = append(ret, secretStr...)
					ret = append(ret, "")
				}
			}

			c.UI.Output(base.WrapForHelpText(ret))
			return true, nil

		case "json":
			if ok := c.PrintJsonItem(c.sar); !ok {
				return false, fmt.Errorf("Error formatting as JSON")
			}
			return true, nil
		}
	}

	return false, nil
}

var keySubstMap = map[string]string{
	"default_port": "Default Port",
}

func exampleOutput() string {
	item := &targets.Target{
		Id:      "ttcp_1234567890",
		ScopeId: scope.Global.String(),
		Scope: &scopes.ScopeInfo{
			Id: scope.Global.String(),
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
		ApplicationCredentialSourceIds: []string{"clvlt_1234567890", "clvlt_0987654321"},
		ApplicationCredentialSources: []*targets.CredentialSource{
			{
				Id:                "clvlt_1234567890",
				CredentialStoreId: "csvlt_1234567890",
			},
			{
				Id:                "clvlt_098765421",
				CredentialStoreId: "clvlt_0987654321",
			},
		},
		Attributes: map[string]interface{}{
			"default_port": 22,
		},
	}
	target := new(targets.TargetReadResult)
	target.Item = item
	return printItemTable(target)
}
