// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billingcmd

import (
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/billing"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/go-wordwrap"
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
	flagStartTime      string
	flagEndTime        string
	monthlyActiveUsers *billing.MonthlyActiveUsersResult
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"monthly-active-users": {"start-time", "end-time"},
	}
}

func extraSynopsisFuncImpl(c *Command) string {
	switch c.Func {
	case "monthly-active-users":
		var in string
		switch {
		case strings.HasPrefix(c.Func, "start-time"):
			in = "Get monthly active users, starting from this time (YYYY-MM format)."
		case strings.HasPrefix(c.Func, "end-time"):
			in = "Get monthly active users, ending at this time (YYYY-MM format)."
		}
		return wordwrap.WrapString(in, base.TermWidth)

	default:
		return ""
	}
}

func extraFlagsFuncImpl(c *Command, _ *base.FlagSets, f *base.FlagSet) {
	flagsMap[c.Func] = append(flagsMap[c.Func], "start-time", "end-time")
	f.StringVar(&base.StringVar{
		Name:   "start-time",
		Target: &c.flagStartTime,
		Usage:  "Get monthly active users, starting from this time (YYYY-MM format).",
	})
	f.StringVar(&base.StringVar{
		Name:   "end-time",
		Target: &c.flagEndTime,
		Usage:  "Get monthly active users, ending at this time (YYYY-MM format).",
	})
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]billing.Option) bool {
	switch c.Func {
	case "monthly-active-users":
		if len(c.flagStartTime) != 0 {
			*opts = append(*opts, billing.WithStartTime(c.flagStartTime))
		}
		if len(c.flagEndTime) != 0 {
			*opts = append(*opts, billing.WithEndTime(c.flagEndTime))
		}
	}

	return true
}

func executeExtraActionsImpl(c *Command, origResp *api.Response, origError error, billingClient *billing.Client, _ uint32, opts []billing.Option) (*api.Response, error) {
	switch c.Func {
	case "monthly-active-users":
		var err error
		c.monthlyActiveUsers, err = billingClient.MonthlyActiveUsers(c.Context, opts...)
		if err != nil {
			return nil, err
		}
	}
	return origResp, origError
}

func printCustomActionOutputImpl(c *Command) (bool, error) {
	switch c.Func {
	case "monthly-active-users":
		switch base.Format(c.UI) {
		case "table":
			items := c.monthlyActiveUsers.GetItems().([]*billing.ActiveUsers)
			var ret []string

			ret = append(ret, "Billing information:")
			ret = append(ret, "")
			for i := range items {
				ret = append(ret,
					fmt.Sprintf("  Count:      %d", items[i].Count),
					fmt.Sprintf("  Start Time: %s", items[i].StartTime),
					fmt.Sprintf("  End Time:   %s", items[i].EndTime),
					"",
				)
			}

			c.UI.Output(base.WrapForHelpText(ret))
			return true, nil

		case "json":
			if ok := c.PrintJsonItem(c.monthlyActiveUsers.GetResponse()); !ok {
				return false, fmt.Errorf("error formatting as JSON")
			}
			return true, nil
		}
	}

	return false, nil
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary billing [sub command] [options] [args]",
			"",
			"  This command allows for collecting Boundary billing reports. Example:",
			"",
			"    Monthly active users:",
			"",
			`      $ boundary billing monthly-active-users`,
			"",
			"  Please see the billing subcommand help for detailed usage information.",
		})
	case "monthly-active-users":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary billing monthly-active-users [options]",
			"",
			"  This command allows for collecting active Boundary user reports, by month. Example:",
			"",
			"    Monthly active users between September 2023 and February 2024:",
			"",
			`      $ boundary billing monthly-active-users -start-time="2023-09" -end-time="2024-02"`,
			"",
			"  Please see the billing subcommand help for detailed usage information.",
		})
	}
	return helpStr + c.Flags().Help()
}
