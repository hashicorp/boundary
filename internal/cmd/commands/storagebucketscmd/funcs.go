// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storagebucketscmd

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/storagebuckets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-bexpr"
)

func init() {
	extraFlagsFunc = extraFlagsFuncImpl
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraFlagsHandlingFunc = extraFlagHandlingFuncImpl
}

const (
	bucketNameFlagName   = "bucket-name"
	bucketPrefixFlagName = "bucket-prefix"
	workerFilterFlagName = "worker-filter"
)

type extraCmdVars struct {
	flagBucketName   string
	flagBucketPrefix string
	flagWorkerFilter string
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	flags := map[string][]string{
		"create": {
			bucketNameFlagName,
			bucketPrefixFlagName,
			workerFilterFlagName,
		},
		"update": {
			workerFilterFlagName,
		},
	}
	return flags
}

func extraFlagsFuncImpl(c *Command, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Storage Bucket Options")

	for _, name := range flagsMap[c.Func] {
		switch name {
		case bucketNameFlagName:
			f.StringVar(&base.StringVar{
				Name:   bucketNameFlagName,
				Target: &c.flagBucketName,
				Usage:  "The bucket name within the external object store.",
			})
		case bucketPrefixFlagName:
			f.StringVar(&base.StringVar{
				Name:   bucketPrefixFlagName,
				Target: &c.flagBucketPrefix,
				Usage:  "The optional bucket prefix to use.",
			})

		case workerFilterFlagName:
			f.StringVar(&base.StringVar{
				Name:   workerFilterFlagName,
				Target: &c.flagWorkerFilter,
				Usage:  `A boolean expression to filter which workers can handle communication to this storage bucket.`,
			})
		}
	}
}

func extraFlagHandlingFuncImpl(c *Command, f *base.FlagSets, opts *[]storagebuckets.Option) bool {
	switch c.flagBucketName {
	case "":
	default:
		*opts = append(*opts, storagebuckets.WithBucketName(c.flagBucketName))
	}
	switch c.flagBucketPrefix {
	case "":
	default:
		*opts = append(*opts, storagebuckets.WithBucketPrefix(c.flagBucketPrefix))
	}

	switch c.flagWorkerFilter {
	case "":
	case "null":
		*opts = append(*opts, storagebuckets.DefaultWorkerFilter())
	default:
		if _, err := bexpr.CreateEvaluator(c.flagWorkerFilter); err != nil {
			c.UI.Error(fmt.Sprintf("Unable to successfully parse filter expression: %s", err))
			return false
		}
		*opts = append(*opts, storagebuckets.WithWorkerFilter(c.flagWorkerFilter))
	}

	return true
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary storage-buckets [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary storage bucket resources. Example:",
			"",
			"    Read a storage bucket:",
			"",
			`      $ boundary storage-buckets read -id sb_1234567890`,
			"",
			"  Please see the storage-buckets subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary storage-buckets create [sub command] [options] [args]",
			"",
			"  This command allows create operations on Boundary storage bucket resources. Example:",
			"",
			"    Create a storage bucket:",
			"",
			`      $ boundary storage-buckets create -plugin-name aws -bucket-name prod_bucket`,
			"",
			"  Please see the subcommand help for detailed usage information.",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary storage-buckets update [sub command] [options] [args]",
			"",
			"  This command allows update operations on Boundary storage bucket resources. Example:",
			"",
			"    Update a storage bucket:",
			"",
			`      $ boundary storage-buckets update -id sb_1234567890 -name devops -description "For DevOps usage"`,
			"",
			"  Please see the subcommand help for detailed usage information.",
		})
	default:
		helpStr = helpMap["base"]()
	}
	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*storagebuckets.StorageBucket) string {
	if len(items) == 0 {
		return "No storage buckets found"
	}

	var output []string
	output = []string{
		"",
		"Storage Bucket information:",
	}
	for i, m := range items {
		if i > 0 {
			output = append(output, "")
		}
		if m.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                       %s", m.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                        %s", "(not available)"),
			)
		}
		if m.BucketName != "" {
			output = append(output,
				fmt.Sprintf("    Bucket Name:             %s", m.BucketName),
			)
		}
		if m.BucketPrefix != "" {
			output = append(output,
				fmt.Sprintf("    Bucket Prefix:           %s", m.BucketPrefix),
			)
		}
		if m.WorkerFilter != "" {
			output = append(output,
				fmt.Sprintf("    Worker Filter:           %s", m.WorkerFilter),
			)
		}
		if c.FlagRecursive && m.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:                %s", m.ScopeId),
			)
		}
		if m.PluginId != "" {
			output = append(output,
				fmt.Sprintf("    Plugin ID:               %s", m.PluginId),
			)
		}
		if m.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:                 %d", m.Version),
			)
		}
		if m.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                    %s", m.Name),
			)
		}
		if m.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:             %s", m.Description),
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

func printItemTable(item *storagebuckets.StorageBucket, resp *api.Response) string {
	nonAttributeMap := map[string]any{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.BucketName != "" {
		nonAttributeMap["Bucket Name"] = item.BucketName
	}
	if item.BucketPrefix != "" {
		nonAttributeMap["Bucket Prefix"] = item.BucketPrefix
	}
	if item.WorkerFilter != "" {
		nonAttributeMap["Worker Filter"] = item.WorkerFilter
	}
	if item.Version != 0 {
		nonAttributeMap["Version"] = item.Version
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
	if item.PluginId != "" {
		nonAttributeMap["Plugin ID"] = item.PluginId
	}
	if item.SecretsHmac != "" {
		nonAttributeMap["Secrets HMAC"] = item.SecretsHmac
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, item.Attributes, keySubstMap)

	ret := []string{
		"",
		"Storage Bucket information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope:",
			base.ScopeInfoForOutput(item.Scope, maxLength),
		)
	}

	if item.Plugin != nil {
		ret = append(ret,
			"",
			"  Plugin:",
			base.PluginInfoForOutput(item.Plugin, maxLength),
		)
	}

	if len(item.Attributes) > 0 {
		ret = append(ret,
			"",
			"  Attributes:",
			base.WrapMap(4, maxLength, item.Attributes),
		)
	}

	if len(item.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, item.AuthorizedActions),
		)
	}

	return base.WrapForHelpText(ret)
}

var keySubstMap = map[string]string{
	"region":   "Region",
	"endpoint": "Endpoint",
}
