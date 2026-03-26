// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/api/proxy"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

const (
	kubeSynopsis = "Authorize a session against a target and invoke a Kubernetes client to connect"
)

func kubeOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("Kubernetes Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagKubeStyle,
		EnvVar:     fmt.Sprintf("BOUNDARY_CONNECT_%s_STYLE", strings.ToUpper(c.Func)),
		Completion: complete.PredictSet("kubectl"),
		Default:    "kubectl",
		Usage:      `Specifies how the CLI will attempt to invoke a Kubernetes client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "kubectl".`,
	})

	f.StringVar(&base.StringVar{
		Name:       "host",
		Target:     &c.flagKubeHost,
		EnvVar:     fmt.Sprintf("BOUNDARY_CONNECT_%s_HOST", strings.ToUpper(c.Func)),
		Completion: complete.PredictNothing,
		Usage:      `Specifies the host value to use, overriding the endpoint address from the session information. The specified hostname will be passed through to the client (if supported) for use in the TLS SNI value.`,
	})

	f.StringVar(&base.StringVar{
		Name:       "scheme",
		Target:     &c.flagKubeScheme,
		Default:    "https",
		EnvVar:     fmt.Sprintf("BOUNDARY_CONNECT_%s_SCHEME", strings.ToUpper(c.Func)),
		Completion: complete.PredictNothing,
		Usage:      `Specifies the scheme to use.`,
	})
}

type kubeFlags struct {
	flagKubeStyle  string
	flagKubeHost   string
	flagKubeScheme string
}

func (f *kubeFlags) defaultExec() string {
	return strings.ToLower(f.flagKubeStyle)
}

func (f *kubeFlags) buildArgs(c *Command, port, ip, addr string, creds proxy.Credentials) ([]string, proxy.Credentials, error) {
	var args []string
	var saToken string

	host := f.flagKubeHost
	if host == "" && c.sessInfo.Endpoint != "" {
		hostUrl := c.sessInfo.Endpoint
		u, err := url.Parse(hostUrl)
		if err != nil {
			return nil, creds, fmt.Errorf("error parsing endpoint URL: %w", err)
		}
		host = u.Hostname()
	}

	retCreds := creds
	if len(retCreds.Password) > 0 {
		// Mark credential as consumed so that it is not printed to user
		retCreds.Password[0].Consumed = true

		// Grab the first username password credential brokered
		saToken = retCreds.Password[0].Password
	}

	switch f.flagKubeStyle {
	case "kubectl":
		if host != "" && f.flagKubeScheme == "https" {
			host = strings.TrimSuffix(host, "/")
			args = append(args, "--tls-server-name", host)
		}
		args = append(args, "--server", fmt.Sprintf("%s://%s", f.flagKubeScheme, addr))

		if saToken != "" {
			args = append(args, "--token", saToken)
		}
	}
	return args, retCreds, nil
}
