package targetscmd

import (
	"fmt"
	"net/textproto"
	"strconv"
	"time"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-bexpr"
)

var extraTcpActionsFlagsMap = map[string][]string{
	"create": {"default-port", "session-max-seconds", "session-connection-limit", "worker-filter"},
	"update": {"default-port", "session-max-seconds", "session-connection-limit", "worker-filter"},
}

type extraTcpCmdVars struct {
	flagDefaultPort            string
	flagSessionMaxSeconds      string
	flagSessionConnectionLimit string
	flagWorkerFilter           string
}

func (c *TcpCommand) extraTcpSynopsisFunc() string {
	return fmt.Sprintf("%s a tcp-type target", textproto.CanonicalMIMEHeaderKey(c.Func))
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
			"Usage: boundary targets tcp update [options] [args]",
			"",
			"  Update a tcp-type target given its ID. Example:",
			"",
			`    $ boundary targets tcp update -id ttcp_1234567890 -name "devops" -description "Tcp target for DevOps"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func (c *TcpCommand) extraTcpFlagsFunc(set *base.FlagSets, f *base.FlagSet) {
	f = set.NewFlagSet("TCP Target Options")

	for _, name := range flagsTcpMap[c.Func] {
		switch name {
		case "default-port":
			f.StringVar(&base.StringVar{
				Name:   "default-port",
				Target: &c.flagDefaultPort,
				Usage:  "The default port to set on the target.",
			})
		case "session-max-seconds":
			f.StringVar(&base.StringVar{
				Name:   "session-max-seconds",
				Target: &c.flagSessionMaxSeconds,
				Usage:  `The maximum lifetime of the session, including all connections. Can be specified as an integer number of seconds or a duration string.`,
			})
		case "session-connection-limit":
			f.StringVar(&base.StringVar{
				Name:   "session-connection-limit",
				Target: &c.flagSessionConnectionLimit,
				Usage:  "The maximum number of connections allowed for a session. -1 means unlimited.",
			})
		case "worker-filter":
			f.StringVar(&base.StringVar{
				Name:   "worker-filter",
				Target: &c.flagWorkerFilter,
				Usage:  "A boolean expression to filter which workers can handle sessions for this target.",
			})
		}
	}
}

func (c *TcpCommand) extraTcpFlagHandlingFunc(opts *[]targets.Option) int {
	switch c.flagDefaultPort {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultTcpTargetDefaultPort())
	default:
		port, err := strconv.ParseUint(c.flagDefaultPort, 10, 32)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error parsing %q: %s", c.flagDefaultPort, err))
			return 1
		}
		*opts = append(*opts, targets.WithTcpTargetDefaultPort(uint32(port)))
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
				return 1
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
			return 1
		}
		*opts = append(*opts, targets.WithSessionConnectionLimit(int32(limit)))
	}

	switch c.flagWorkerFilter {
	case "":
	case "null":
		*opts = append(*opts, targets.DefaultWorkerFilter())
	default:
		if _, err := bexpr.CreateEvaluator(c.flagWorkerFilter); err != nil {
			c.UI.Error(fmt.Sprintf("Unable to successfully parse filter expression: %s", err))
			return 1
		}
		*opts = append(*opts, targets.WithWorkerFilter(c.flagWorkerFilter))
	}

	return 0
}
