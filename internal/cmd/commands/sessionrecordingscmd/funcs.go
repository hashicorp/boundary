// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sessionrecordingscmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/sessionrecordings"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/recording"
)

type extraCmdVars struct{}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary session-recordings [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary session recordings.",
			"",
			"    Read a session recording:",
			"",
			`      $ boundary session-recordings read -id s_1234567890`,
			"",
			"    List session recording:",
			"",
			`      $ boundary session-recordings list -scope-id global`,
			"",
			"    Download a session recording:",
			"",
			`      $ boundary session-recordings download -id chr_1234567890`,
			"",

			"  Please see the sessions subcommand help for detailed usage information.",
		})

	default:
		helpStr = helpMap["base"]()
	}

	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*sessionrecordings.SessionRecording) string {
	if len(items) == 0 {
		return "No session recordings found"
	}
	var output []string
	output = []string{
		"",
		"Session Recording information:",
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
		if c.FlagRecursive && item.Scope.Id != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.Scope.Id),
			)
		}
		if item.SessionId != "" {
			output = append(output,
				fmt.Sprintf("    Session ID:          %s", item.SessionId),
			)
		}
		if item.StorageBucketId != "" {
			output = append(output,
				fmt.Sprintf("    Storage Bucket ID:   %s", item.StorageBucketId),
			)
		}
		if !item.CreatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Created Time:        %s", item.CreatedTime.Local().Format(time.RFC1123)),
			)
		}
		if !item.UpdatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Updated Time:        %s", item.UpdatedTime.Local().Format(time.RFC1123)),
			)
		}
		if !item.StartTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Start Time:          %s", item.StartTime.Local().Format(time.RFC1123)),
			)
		}
		if !item.EndTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    End Time:            %s", item.EndTime.Local().Format(time.RFC1123)),
			)
		}
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:                %s", item.Type),
			)
		}
		if item.State != "" {
			output = append(output,
				fmt.Sprintf("    State:               %s", item.State),
			)
		}
		if !item.RetainUntil.IsZero() {
			var retention string
			switch item.RetainUntil {
			case recording.InfinityTS:
				retention = "Forever"
			default:
				retention = item.RetainUntil.Local().Format(time.RFC1123)
			}
			output = append(output,
				fmt.Sprintf("    Retain Until:        %s", retention),
			)
		}
		if !item.DeleteAfter.IsZero() {
			output = append(output,
				fmt.Sprintf("    Delete After:        %s", item.DeleteAfter.Local().Format(time.RFC1123)),
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

func printItemTable(item *sessionrecordings.SessionRecording, resp *api.Response) string {
	const (
		durationKey = "Duration (Seconds)"
	)
	nonAttributeMap := map[string]any{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Scope.Id != "" {
		nonAttributeMap["Scope ID"] = item.Scope.Id
	}
	if item.SessionId != "" {
		nonAttributeMap["Session ID"] = item.SessionId
	}
	if item.StorageBucketId != "" {
		nonAttributeMap["Storage Bucket ID"] = item.StorageBucketId
	}
	if item.BytesUp != 0 {
		nonAttributeMap["Bytes Up"] = item.BytesUp
	}
	if item.BytesDown != 0 {
		nonAttributeMap["Bytes Down"] = item.BytesDown
	}
	if !item.CreatedTime.IsZero() {
		nonAttributeMap["Created Time"] = item.CreatedTime.Local().Format(time.RFC1123)
	}
	if !item.UpdatedTime.IsZero() {
		nonAttributeMap["Updated Time"] = item.UpdatedTime.Local().Format(time.RFC1123)
	}
	if !item.StartTime.IsZero() {
		nonAttributeMap["Start Time"] = item.StartTime.Local().Format(time.RFC1123)
	}
	if !item.EndTime.IsZero() {
		nonAttributeMap["Updated Time"] = item.EndTime.Local().Format(time.RFC1123)
	}
	if item.Duration.Duration != 0 {
		nonAttributeMap[durationKey] = item.Duration.Seconds()
	}
	if !item.RetainUntil.IsZero() {
		var retention string
		switch item.RetainUntil {
		case recording.InfinityTS:
			retention = "Forever"
		default:
			retention = item.RetainUntil.Local().Format(time.RFC1123)
		}
		nonAttributeMap["Retain Until"] = retention
	}
	if !item.DeleteAfter.IsZero() {
		nonAttributeMap["Delete After"] = item.DeleteAfter.Local().Format(time.RFC1123)
	}
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
	}
	if item.State != "" {
		nonAttributeMap["State"] = item.State
	}
	if item.ErrorDetails != "" {
		nonAttributeMap["Error Details"] = item.ErrorDetails
	}
	if len(item.MimeTypes) > 0 {
		nonAttributeMap["Mime Types"] = strings.Join(item.MimeTypes, ", ")
	}
	if item.Endpoint != "" {
		nonAttributeMap["Endpoint"] = item.Endpoint
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Session Recording information:",
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

	if item.CreateTimeValues != nil {
		if item.CreateTimeValues.User != nil {
			userMap := map[string]any{
				"ID": item.CreateTimeValues.User.Id,
			}
			if item.CreateTimeValues.User.Name != "" {
				userMap["Name"] = item.CreateTimeValues.User.Name
			}
			if item.CreateTimeValues.User.Description != "" {
				userMap["Description"] = item.CreateTimeValues.User.Description
			}
			maxUserLength := base.MaxAttributesLength(userMap, nil, nil)
			ret = append(ret,
				"",
				"  User Info:",
				base.WrapMap(4, maxUserLength+2, userMap),
				"    Scope:", customScopeInfoForOutput(item.CreateTimeValues.User.Scope, maxUserLength, 6),
			)
		}
		if item.CreateTimeValues.Target != nil {
			targetMap := map[string]any{
				"ID": item.CreateTimeValues.Target.Id,
			}
			if item.CreateTimeValues.Target.Name != "" {
				targetMap["Name"] = item.CreateTimeValues.Target.Name
			}
			if item.CreateTimeValues.Target.Description != "" {
				targetMap["Description"] = item.CreateTimeValues.Target.Description
			}
			if item.CreateTimeValues.Target.SessionMaxSeconds != 0 {
				targetMap["Session Max Seconds"] = item.CreateTimeValues.Target.SessionMaxSeconds
			}
			if item.CreateTimeValues.Target.SessionConnectionLimit != 0 {
				targetMap["Session Connection Limit"] = item.CreateTimeValues.Target.SessionConnectionLimit
			}
			if item.CreateTimeValues.Target.WorkerFilter != "" {
				targetMap["Worker Filter"] = item.CreateTimeValues.Target.WorkerFilter
			}
			if item.CreateTimeValues.Target.EgressWorkerFilter != "" {
				targetMap["Egress Worker Filter"] = item.CreateTimeValues.Target.EgressWorkerFilter
			}
			if item.CreateTimeValues.Target.IngressWorkerFilter != "" {
				targetMap["Ingress Worker Filter"] = item.CreateTimeValues.Target.IngressWorkerFilter
			}
			if item.CreateTimeValues.Target.Attributes != nil {
				if attr, err := item.CreateTimeValues.Target.GetSshTargetAttributes(); err == nil && attr != nil && attr.DefaultPort != 0 {
					targetMap["Default Port"] = attr.DefaultPort
				}
			}
			maxTargetLength := base.MaxAttributesLength(targetMap, nil, nil)
			ret = append(ret,
				"",
				"  Target Info:",
				base.WrapMap(4, maxTargetLength+2, targetMap),
				"    Scope:", customScopeInfoForOutput(item.CreateTimeValues.Target.Scope, maxTargetLength, 6),
			)
		}
		if item.CreateTimeValues.Host != nil {
			hostMap := map[string]any{
				"ID": item.CreateTimeValues.Host.Id,
			}
			if item.CreateTimeValues.Host.Name != "" {
				hostMap["Name"] = item.CreateTimeValues.Host.Name
			}
			if item.CreateTimeValues.Host.Description != "" {
				hostMap["Description"] = item.CreateTimeValues.Host.Description
			}
			if item.CreateTimeValues.Host.Type != "" {
				hostMap["Type"] = item.CreateTimeValues.Host.Type
			}
			if item.CreateTimeValues.Host.ExternalId != "" {
				hostMap["External ID"] = item.CreateTimeValues.Host.ExternalId
			}
			if item.CreateTimeValues.Host.Attributes != nil {
				if attr, err := item.CreateTimeValues.Host.GetStaticHostAttributes(); err == nil && attr != nil && attr.Address != "" {
					hostMap["Address"] = attr.Address
				}
			}
			maxHostLength := base.MaxAttributesLength(hostMap, nil, nil)
			ret = append(ret,
				"",
				"  Host Info:", base.WrapMap(4, maxHostLength+2, hostMap),
			)

			if item.CreateTimeValues.Host.HostCatalog != nil {
				catMap := map[string]any{
					"ID": item.CreateTimeValues.Host.HostCatalog.Id,
				}
				if item.CreateTimeValues.Host.HostCatalog.Name != "" {
					hostMap["Name"] = item.CreateTimeValues.Host.HostCatalog.Name
				}
				if item.CreateTimeValues.Host.HostCatalog.Description != "" {
					hostMap["Description"] = item.CreateTimeValues.Host.HostCatalog.Description
				}
				if item.CreateTimeValues.Host.HostCatalog.PluginId != "" {
					hostMap["Plugin ID"] = item.CreateTimeValues.Host.HostCatalog.PluginId
				}
				if item.CreateTimeValues.Host.HostCatalog.Type != "" {
					hostMap["Type"] = item.CreateTimeValues.Host.HostCatalog.Type
				}
				maxCatLength := base.MaxAttributesLength(catMap, nil, nil)

				ret = append(ret,
					"    HostCatalog:", base.WrapMap(6, maxCatLength, catMap),
					"      Scope:", customScopeInfoForOutput(item.CreateTimeValues.Host.HostCatalog.Scope, maxHostLength, 8),
				)
			}
		}
		if len(item.CreateTimeValues.CredentialLibraries) > 0 {
			ret = append(ret,
				"",
				"  Credential Libraries:")
			for _, cl := range item.CreateTimeValues.CredentialLibraries {
				cm := map[string]any{
					"ID": cl.Id,
				}
				if cl.Name != "" {
					cm["Name"] = cl.Name
				}
				if cl.Description != "" {
					cm["Description"] = cl.Description
				}
				if cl.Type != "" {
					cm["Type"] = cl.Type
				}
				if len(cl.Purposes) > 0 {
					cm["Purpose"] = strings.Join(cl.Purposes, ", ")
				}
				if attrs, _ := cl.GetVaultSSHCertificateCredentialLibraryAttributes(); attrs != nil {
					if attrs.Path != "" {
						cm["Vault Path"] = attrs.Path
					}
					if attrs.Username != "" {
						cm["Username"] = attrs.Username
					}
					if attrs.KeyType != "" {
						cm["Key Type"] = attrs.KeyType
					}
					if attrs.Ttl != "" {
						cm["Ttl"] = attrs.Ttl
					}
				}
				if attrs, _ := cl.GetVaultCredentialLibraryAttributes(); attrs != nil {
					if attrs.Path != "" {
						cm["Vault Path"] = attrs.Path
					}
					if attrs.HttpMethod != "" {
						cm["Http Method"] = attrs.HttpMethod
					}
					if attrs.HttpRequestBody != "" {
						cm["Http Request Body"] = attrs.HttpRequestBody
					}
				}
				maxLibLength := base.MaxAttributesLength(cm, nil, nil)
				ret = append(ret,
					base.WrapMap(4, maxLibLength, cm),
					"",
				)
				if cs := cl.CredentialStore; cs != nil {
					csm := credStoreMap(cs)
					maxStoreLength := base.MaxAttributesLength(csm, nil, nil)
					ret = append(ret,
						"    Credential Store:",
						base.WrapMap(6, maxStoreLength, csm),
						"",
					)
				}
			}
		}

		if len(item.CreateTimeValues.Credentials) > 0 {
			ret = append(ret,
				"",
				"  Credentials:")
			for _, c := range item.CreateTimeValues.Credentials {
				cm := map[string]any{
					"ID": c.Id,
				}
				if c.Name != "" {
					cm["Name"] = c.Name
				}
				if c.Description != "" {
					cm["Description"] = c.Description
				}
				if c.Type != "" {
					cm["Type"] = c.Type
				}
				if len(c.Purposes) > 0 {
					cm["Purpose"] = strings.Join(c.Purposes, ", ")
				}
				if attrs, _ := c.GetJsonCredentialAttributes(); attrs != nil {
					if attrs.ObjectHmac != "" {
						cm["Object HMAC"] = attrs.ObjectHmac
					}
				}
				if attrs, _ := c.GetUsernamePasswordCredentialAttributes(); attrs != nil {
					if attrs.Username != "" {
						cm["Username"] = attrs.Username
					}
				}
				if attrs, _ := c.GetSshPrivateKeyCredentialAttributes(); attrs != nil {
					if attrs.Username != "" {
						cm["Username"] = attrs.Username
					}
				}
				maxLibLength := base.MaxAttributesLength(cm, nil, nil)
				ret = append(ret,
					base.WrapMap(4, maxLibLength, cm),
					"",
				)
				if cs := c.CredentialStore; cs != nil {
					csm := credStoreMap(cs)
					maxStoreLength := base.MaxAttributesLength(csm, nil, nil)
					ret = append(ret,
						"    Credential Store:",
						base.WrapMap(6, maxStoreLength, csm),
						"",
					)
				}
			}
		}
	}

	if len(item.ConnectionRecordings) > 0 {
		maxAttrLen := len(durationKey)
		ret = append(ret,
			"",
			"  Connections Recordings:",
		)
		for _, cr := range item.ConnectionRecordings {
			cm := map[string]any{
				"ID": cr.Id,
			}
			if cr.BytesUp != 0 {
				cm["Bytes Up"] = cr.BytesUp
			}
			if cr.BytesDown != 0 {
				cm["Bytes Down"] = cr.BytesDown
			}
			if !cr.CreatedTime.IsZero() {
				cm["Created Time"] = cr.CreatedTime.Local().Format(time.RFC1123)
			}
			if !cr.UpdatedTime.IsZero() {
				cm["Updated Time"] = cr.UpdatedTime.Local().Format(time.RFC1123)
			}
			if !cr.StartTime.IsZero() {
				cm["Start Time"] = cr.StartTime.Local().Format(time.RFC1123)
			}
			if !cr.EndTime.IsZero() {
				cm["End Time"] = cr.EndTime.Local().Format(time.RFC1123)
			}
			if cr.Duration.Duration != 0 {
				cm[durationKey] = cr.Duration.Seconds()
			}
			if len(cr.MimeTypes) > 0 {
				cm["Mime Types"] = strings.Join(cr.MimeTypes, ", ")
			}
			ret = append(ret,
				base.WrapMap(4, maxAttrLen, cm),
				"",
			)

			if len(cr.ChannelRecordings) > 0 {
				var channelRecordings []map[string]any
				for _, chr := range cr.ChannelRecordings {
					chrm := map[string]any{
						"ID": chr.Id,
					}
					if chr.BytesUp != 0 {
						chrm["Bytes Up"] = chr.BytesUp
					}
					if chr.BytesDown != 0 {
						chrm["Bytes Down"] = chr.BytesDown
					}
					if !chr.CreatedTime.IsZero() {
						chrm["Created Time"] = chr.CreatedTime.Local().Format(time.RFC1123)
					}
					if !chr.UpdatedTime.IsZero() {
						chrm["Updated Time"] = chr.UpdatedTime.Local().Format(time.RFC1123)
					}
					if !chr.StartTime.IsZero() {
						chrm["Start Time"] = chr.StartTime.Local().Format(time.RFC1123)
					}
					if !chr.EndTime.IsZero() {
						chrm["End Time"] = chr.EndTime.Local().Format(time.RFC1123)
					}
					if chr.Duration.Duration != 0 {
						chrm[durationKey] = chr.Duration.Seconds()
					}
					if len(chr.MimeTypes) > 0 {
						chrm["Mime Types"] = strings.Join(chr.MimeTypes, ", ")
					}
					channelRecordings = append(channelRecordings, chrm)
				}
				ret = append(ret,
					"",
					"    Channel Recordings:",
				)
				for _, cr := range channelRecordings {
					ret = append(ret,
						base.WrapMap(6, maxAttrLen, cr),
						"",
					)
				}
			}
		}
	}
	return base.WrapForHelpText(ret)
}

func credStoreMap(cs *sessionrecordings.CredentialStore) map[string]any {
	csm := map[string]any{
		"ID": cs.Id,
	}
	if cs.Name != "" {
		csm["Name"] = cs.Name
	}
	if cs.Description != "" {
		csm["Description"] = cs.Description
	}
	if cs.ScopeId != "" {
		csm["Scope ID"] = cs.ScopeId
	}
	if cs.Type != "" {
		csm["Type"] = cs.Type
	}
	if attrs, _ := cs.GetVaultCredentialStoreAttributes(); attrs != nil {
		if attrs.Address != "" {
			csm["Vault Address"] = attrs.Address
		}
		if attrs.Namespace != "" {
			csm["Namespace"] = attrs.Namespace
		}
		if attrs.WorkerFilter != "" {
			csm["Worker Filter"] = attrs.WorkerFilter
		}
	}
	return csm
}

func customScopeInfoForOutput(scp *scopes.ScopeInfo, maxLength int, prefixSpaces int) string {
	if scp == nil {
		return "    <not included in response>"
	}
	vals := map[string]any{
		"ID":   scp.Id,
		"Type": scp.Type,
		"Name": scp.Name,
	}
	if scp.ParentScopeId != "" {
		vals["Parent Scope ID"] = scp.ParentScopeId
	}
	return base.WrapMap(prefixSpaces, maxLength, vals)
}
