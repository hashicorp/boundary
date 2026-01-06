// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package targetscmd

import (
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-bexpr"
)

func init() {
	extraTcpActionsFlagsMapFunc = extraTcpActionsFlagsMapFuncImpl
	extraTcpFlagsFunc = extraTcpFlagsFuncImpl
	extraTcpFlagsHandlingFunc = extraTcpFlagsHandlingFuncImpl
}

func extraTcpActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {
			"address", "default-port", "default-client-port", "session-max-seconds",
			"session-connection-limit", "egress-worker-filter", "ingress-worker-filter",
			"with-alias-value", "with-alias-scope-id", "with-alias-authorize-session-host-id",
		},
		"update": {
			"address", "default-port", "default-client-port", "session-max-seconds",
			"session-connection-limit", "worker-filter", "egress-worker-filter",
			"ingress-worker-filter",
		},
	}
}

type extraTcpCmdVars struct {
	flagDefaultPort            string
	flagDefaultClientPort      string
	flagSessionMaxSeconds      string
	flagSessionConnectionLimit string
	flagWorkerFilter           string
	flagEgressWorkerFilter     string
	flagIngressWorkerFilter    string
	flagAddress                string
	flagWithAliasValue         string
	flagWithAliasScopeId       string
	flagWithAliasHostId        string
}

func (c *TcpCommand) extraTcpHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary targets create tcp [options] [args]",
			"",
			"  Create a tcp-type target. Example:",
			"",
			`    $ boundary targets create tcp -name prodops -description "Tcp target for ProdOps"`,
			"",
			"",
		})

	case "update":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary targets update tcp [options] [args]",
			"",
			"  Update a tcp-type target given its ID. Example:",
			"",
			`    $ boundary targets update tcp -id ttcp_1234567890 -name "devops" -description "Tcp target for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraTcpFlagsFuncImpl(c *TcpCommand, set *base.FlagSets, f *base.FlagSet) {
	fs := set.NewFlagSet("TCP Target Options")

	for _, name := range flagsTcpMap[c.Func] {
		switch name {
		case "address":
			fs.StringVar(&base.StringVar{
				Name:   "address",
				Target: &c.flagAddress,
				Usage:  "Optionally, a valid network address to connect to for this target. Can not be used alongside host sources.",
			})
		case "default-port":
			fs.StringVar(&base.StringVar{
				Name:   "default-port",
				Target: &c.flagDefaultPort,
				Usage:  "The default port to set on the target.",
			})
		case "default-client-port":
			fs.StringVar(&base.StringVar{
				Name:   "default-client-port",
				Target: &c.flagDefaultClientPort,
				Usage:  "The default client port to set on the target.",
			})
		case "session-max-seconds":
			fs.StringVar(&base.StringVar{
				Name:   "session-max-seconds",
				Target: &c.flagSessionMaxSeconds,
				Usage:  `The maximum lifetime of the session, including all connections. Can be specified as an integer number of seconds or a duration string.`,
			})
		case "session-connection-limit":
			fs.StringVar(&base.StringVar{
				Name:   "session-connection-limit",
				Target: &c.flagSessionConnectionLimit,
				Usage:  "The maximum number of connections allowed for a session. -1 means unlimited.",
			})
		case "worker-filter":
			fs.StringVar(&base.StringVar{
				Name:   "worker-filter",
				Target: &c.flagWorkerFilter,
				Usage:  "Deprecated: use egress or ingress filters instead.",
			})
		case "egress-worker-filter":
			fs.StringVar(&base.StringVar{
				Name:   "egress-worker-filter",
				Target: &c.flagEgressWorkerFilter,
				Usage:  "A boolean expression to filter which egress workers can handle sessions for this target.",
			})
		case "ingress-worker-filter":
			fs.StringVar(&base.StringVar{
				Name:   "ingress-worker-filter",
				Target: &c.flagIngressWorkerFilter,
				Usage:  "A boolean expression to filter which ingress workers can handle sessions for this target.",
			})
		case "with-alias-value":
			fs.StringVar(&base.StringVar{
				Name:   "with-alias-value",
				Target: &c.flagWithAliasValue,
				Usage:  "The value for an alias to be created for and at the same time as this target.",
			})
		case "with-alias-scope-id":
			fs.StringVar(&base.StringVar{
				Name:    "with-alias-scope-id",
				Target:  &c.flagWithAliasScopeId,
				Default: "global",
				Usage:   "The scope id for an alias to be created for and at the same time as this target.",
			})
		case "with-alias-authorize-session-host-id":
			fs.StringVar(&base.StringVar{
				Name:   "with-alias-authorize-session-host-id",
				Target: &c.flagWithAliasHostId,
				Usage:  "The authorize session host id flag used by an alias to be created for and at the same time as this target.",
			})
		}
	}
}

func extraTcpFlagsHandlingFuncImpl(c *TcpCommand, _ *base.FlagSets, opts *[]targets.Option) bool {
	switch c.flagDefaultPort {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultTcpTargetDefaultPort())
	default:
		port, err := strconv.ParseUint(c.flagDefaultPort, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagDefaultPort, err))
			return false
		}
		*opts = append(*opts, targets.WithTcpTargetDefaultPort(uint32(port)))
	}

	switch c.flagDefaultClientPort {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultTcpTargetDefaultClientPort())
	default:
		port, err := strconv.ParseUint(c.flagDefaultClientPort, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagDefaultClientPort, err))
			return false
		}
		*opts = append(*opts, targets.WithTcpTargetDefaultClientPort(uint32(port)))
	}

	switch c.flagSessionMaxSeconds {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultSessionMaxSeconds())
	default:
		var final uint32
		dur, err := strconv.ParseUint(c.flagSessionMaxSeconds, 10, 32)
		if err == nil {
			final = uint32(dur)
		} else {
			dur, err := time.ParseDuration(c.flagSessionMaxSeconds)
			if err != nil {
				c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagSessionMaxSeconds, err))
				return false
			}
			final = uint32(dur.Seconds())
		}
		*opts = append(*opts, targets.WithSessionMaxSeconds(final))
	}

	switch c.flagSessionConnectionLimit {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultSessionConnectionLimit())
	default:
		limit, err := strconv.ParseInt(c.flagSessionConnectionLimit, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagSessionConnectionLimit, err))
			return false
		}
		*opts = append(*opts, targets.WithSessionConnectionLimit(int32(limit)))
	}

	switch c.flagWorkerFilter {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultWorkerFilter())
	default:
		if _, err := bexpr.CreateEvaluator(c.flagWorkerFilter); err != nil {
			c.UI.Error(fmt.Sprintf("Unable to successfully parse worker filter expression: %s", err))
			return false
		}
		*opts = append(*opts, targets.WithWorkerFilter(c.flagWorkerFilter))
	}

	switch c.flagEgressWorkerFilter {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultEgressWorkerFilter())
	default:
		if _, err := bexpr.CreateEvaluator(c.flagEgressWorkerFilter); err != nil {
			c.UI.Error(fmt.Sprintf("Unable to successfully parse egress filter expression: %s", err))
			return false
		}
		*opts = append(*opts, targets.WithEgressWorkerFilter(c.flagEgressWorkerFilter))
	}
	switch c.flagIngressWorkerFilter {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultIngressWorkerFilter())
	default:
		if _, err := bexpr.CreateEvaluator(c.flagIngressWorkerFilter); err != nil {
			c.UI.Error(fmt.Sprintf("Unable to successfully parse ingress filter expression: %s", err))
			return false
		}
		*opts = append(*opts, targets.WithIngressWorkerFilter(c.flagIngressWorkerFilter))
	}

	switch c.flagAddress {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultAddress())
	default:
		*opts = append(*opts, targets.WithAddress(c.flagAddress))
	}

	var aliasValue string
	switch c.flagWithAliasValue {
	case "":
	case "null":
		c.UI.Error("The with-alias-value flag cannot be set to null")
		return false
	default:
		aliasValue = c.flagWithAliasValue
	}

	var aliasScopeId string
	switch c.flagWithAliasScopeId {
	case "":
	case "null":
		c.UI.Error("The with-alias-scope-id flag cannot be set to null")
		return false
	default:
		aliasScopeId = c.flagWithAliasScopeId
	}

	var aliasHostId string
	switch c.flagWithAliasHostId {
	case "":
	case "null":
		c.UI.Error("The with-alias-authorize-session-host-id flag cannot be set to null")
		return false
	default:
		aliasHostId = c.flagWithAliasHostId
	}

	switch {
	case aliasValue != "" && aliasScopeId == "":
		c.UI.Error("The with-alias-value flag must be used with the with-alias-scope-id flag")
		return false
	case aliasValue != "" && aliasScopeId != "":
		a := targets.Alias{
			Value:   aliasValue,
			ScopeId: aliasScopeId,
		}
		if aliasHostId != "" {
			a.Attributes = &targets.TargetAliasAttributes{
				AuthorizeSessionArguments: &targets.AuthorizeSessionArguments{
					HostId: aliasHostId,
				},
			}
		}
		*opts = append(*opts, targets.WithAliases([]targets.Alias{a}))
	}

	return true
}
