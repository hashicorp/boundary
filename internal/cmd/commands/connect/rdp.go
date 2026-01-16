// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"fmt"
	"net/url"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

const (
	rdpSynopsis = "Authorize a session against a target and invoke an RDP client to connect"
)

func rdpOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("RDP Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagRdpStyle,
		EnvVar:     "BOUNDARY_CONNECT_RDP_STYLE",
		Completion: complete.PredictSet("mstsc", "open"),
		Usage:      `Specifies how the CLI will attempt to invoke an RDP client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "mstsc", which is the default on Windows and launches the Windows client, and "open", which is the default on Mac and launches via an rdp:// URL.`,
	})
}

type rdpFlags struct {
	flagRdpStyle string
}

func (r *rdpFlags) defaultExec() string {
	r.flagRdpStyle = strings.ToLower(r.flagRdpStyle)
	switch r.flagRdpStyle {
	case "":
		switch runtime.GOOS {
		case "windows":
			r.flagRdpStyle = "mstsc"
		case "darwin":
			r.flagRdpStyle = "open"
		default:
			// We may want to support rdesktop and/or xfreerdp at some point soon
			r.flagRdpStyle = "mstsc"
		}
	}
	if r.flagRdpStyle == "mstsc" {
		r.flagRdpStyle = "mstsc.exe"
	}
	return r.flagRdpStyle
}

func (r *rdpFlags) buildArgs(c *Command, port, ip, addr string) []string {
	var args []string
	switch r.flagRdpStyle {
	case "mstsc.exe":
		args = append(args, "/v", addr)
	case "open":
		args = append(args, "-W", fmt.Sprintf("rdp://full%saddress=s%s%s", "%20", "%3A", url.QueryEscape(addr)))
	}
	return args
}
