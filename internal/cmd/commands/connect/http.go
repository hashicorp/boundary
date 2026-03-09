// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

const (
	httpSynopsis = "Authorize a session against a target and invoke an HTTP client to connect"
)

func httpOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("HTTP Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagHttpStyle,
		EnvVar:     "BOUNDARY_CONNECT_HTTP_STYLE",
		Completion: complete.PredictSet("curl"),
		Default:    "curl",
		Usage:      `Specifies how the CLI will attempt to invoke an HTTP client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "curl".`,
	})

	f.StringVar(&base.StringVar{
		Name:       "host",
		Target:     &c.flagHttpHost,
		EnvVar:     "BOUNDARY_CONNECT_HTTP_HOST",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the host value to use, overriding the endpoint address from the session information. The specified hostname will be passed through to the client (if supported) for use in the Host header and TLS SNI value.`,
	})

	f.StringVar(&base.StringVar{
		Name:       "path",
		Target:     &c.flagHttpPath,
		EnvVar:     "BOUNDARY_CONNECT_HTTP_PATH",
		Completion: complete.PredictNothing,
		Usage:      `Specifies a path that will be appended to the generated URL.`,
	})

	f.StringVar(&base.StringVar{
		Name:       "method",
		Target:     &c.flagHttpMethod,
		EnvVar:     "BOUNDARY_CONNECT_HTTP_METHOD",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the method to use. If not set, will use the client's default.`,
	})

	f.StringVar(&base.StringVar{
		Name:       "scheme",
		Target:     &c.flagHttpScheme,
		Default:    "https",
		EnvVar:     "BOUNDARY_CONNECT_HTTP_SCHEME",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the scheme to use.`,
	})
}

type httpFlags struct {
	flagHttpStyle  string
	flagHttpHost   string
	flagHttpPath   string
	flagHttpMethod string
	flagHttpScheme string
}

func (h *httpFlags) defaultExec() string {
	return strings.ToLower(h.flagHttpStyle)
}

func (h *httpFlags) buildArgs(c *Command, port, ip, addr string) ([]string, error) {
	var args []string
	host := h.flagHttpHost
	if host == "" && c.sessInfo.Endpoint != "" {
		hostUrl := c.sessInfo.Endpoint
		u, err := url.Parse(hostUrl)
		if err != nil {
			return nil, fmt.Errorf("error parsing endpoint URL: %w", err)
		}
		host = u.Hostname()
	}
	switch h.flagHttpStyle {
	case "curl":
		if h.flagHttpMethod != "" {
			args = append(args, "-X", h.flagHttpMethod)
		}
		var uri string
		if host != "" {
			host = strings.TrimSuffix(host, "/")
			args = append(args, "-H", fmt.Sprintf("Host: %s", host))
			switch port == "" {
			case false:
				args = append(args, "--resolve", fmt.Sprintf("%s:%s:%s", host, port, ip))
				uri = fmt.Sprintf("%s://%s:%s", h.flagHttpScheme, host, port)
			default:
				args = append(args, "--resolve", fmt.Sprintf("%s:%s", host, ip))
				uri = fmt.Sprintf("%s://%s", h.flagHttpScheme, host)
			}
		} else {
			uri = fmt.Sprintf("%s://%s", h.flagHttpScheme, addr)
		}
		if h.flagHttpPath != "" {
			uri = fmt.Sprintf("%s/%s", uri, strings.TrimPrefix(h.flagHttpPath, "/"))
		}
		args = append(args, uri)
	}
	return args, nil
}
