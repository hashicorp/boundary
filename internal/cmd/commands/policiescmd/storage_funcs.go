// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package policiescmd

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/boundary/api/policies"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraStorageActionsFlagsMapFunc = extraStorageActionsFlagsMapFuncImpl
	extraStorageFlagsFunc = extraStorageFlagsFuncImpl
	extraStorageFlagsHandlingFunc = extraStorageFlagsHandlingFuncImpl
}

type extraStorageCmdVars struct {
	flagRetainForDays          string
	flagRetainForOverridable   string
	flagDeleteAfterDays        string
	flagDeleteAfterOverridable string

	flagRetainFor   map[string]string
	flagDeleteAfter map[string]string
}

func (c *StorageCommand) extraStorageHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary policies create storage [options] [args]",
			"",
			"  Create a storage-type policy. Example:",
			"",
			`    $ boundary policies create storage -name prod -description "Prod Storage Policy" -retain-for-days 800 -retain-for-overridable false -delete-after-days 900 -delete-after-overridable false`,
			"",
			"",
		})
	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary policies update storage [options] [args]",
			"",
			"  Update a storage-type policy given its id. Example:",
			"",
			`    $ boundary policies update storage -id pst_1234567890 -name dev -description "Dev Storage Policy" -retain-for-days 10 -retain-for-overridable null -delete-after-days 20 -delete-after-overridable true`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraStorageActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {"retain-for-days", "retain-for-overridable", "delete-after-days", "delete-after-overridable"},
		"update": {"retain-for-days", "retain-for-overridable", "delete-after-days", "delete-after-overridable"},
	}
}

func extraStorageFlagsFuncImpl(c *StorageCommand, set *base.FlagSets, f *base.FlagSet) {
	fs := set.NewFlagSet("Storage Policy Options")

	for _, name := range flagsStorageMap[c.Func] {
		switch name {
		case "retain-for-days":
			fs.StringVar(&base.StringVar{
				Name:   "retain-for-days",
				Target: &c.flagRetainForDays,
				Usage:  "Number of days a session recording should be retained for.",
			})
		case "retain-for-overridable":
			fs.StringVar(&base.StringVar{
				Name:   "retain-for-overridable",
				Target: &c.flagRetainForOverridable,
				Usage:  "Allow/Disallow this policy's retention period to be overridden by downstream storage policies (true or false).",
			})
		case "delete-after-days":
			fs.StringVar(&base.StringVar{
				Name:   "delete-after-days",
				Target: &c.flagDeleteAfterDays,
				Usage:  "Number of days after which a session recording will be deleted.",
			})
		case "delete-after-overridable":
			fs.StringVar(&base.StringVar{
				Name:   "delete-after-overridable",
				Target: &c.flagDeleteAfterOverridable,
				Usage:  "Allow/Disallow this policy's deletion period to be overridden by downstream Policies (true or false)",
			})
		}
	}
}

func extraStorageFlagsHandlingFuncImpl(c *StorageCommand, _ *base.FlagSets, opts *[]policies.Option) bool {
	rf := map[string]any{}
	da := map[string]any{}

	var withRetainFor, withDeleteAfter bool
	switch c.flagRetainForDays {
	case "":
	case "null":
		rf["days"] = nil
		withRetainFor = true
	default:
		days, err := strconv.ParseInt(c.flagRetainForDays, 10, 64)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagRetainForDays, err))
			return false
		}
		rf["days"] = days
		withRetainFor = true
	}
	switch c.flagRetainForOverridable {
	case "":
	case "null":
		rf["overridable"] = nil
		withRetainFor = true
	default:
		overridable, err := strconv.ParseBool(c.flagRetainForOverridable)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagRetainForOverridable, err))
			return false
		}
		rf["overridable"] = overridable
		withRetainFor = true
	}

	switch c.flagDeleteAfterDays {
	case "":
	case "null":
		da["days"] = nil
		withDeleteAfter = true
	default:
		days, err := strconv.ParseInt(c.flagDeleteAfterDays, 10, 64)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagDeleteAfterDays, err))
			return false
		}
		da["days"] = days
		withDeleteAfter = true
	}
	switch c.flagDeleteAfterOverridable {
	case "":
	case "null":
		da["overridable"] = nil
		withDeleteAfter = true
	default:
		overridable, err := strconv.ParseBool(c.flagDeleteAfterOverridable)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagDeleteAfterOverridable, err))
			return false
		}
		da["overridable"] = overridable
		withDeleteAfter = true
	}

	if withRetainFor {
		*opts = append(*opts, policies.WithStoragePolicyRetainFor(rf))
	}
	if withDeleteAfter {
		*opts = append(*opts, policies.WithStoragePolicyDeleteAfter(da))
	}

	return true
}
