// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-secure-stdlib/listenerutil"
)

// ClientIpFromRequest will determine the client IP of the http request
func ClientIpFromRequest(ctx context.Context, listenerCfg *listenerutil.ListenerConfig, r *http.Request) (string, error) {
	const op = "common.ClientIpFromRequest"
	if r == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing http request")
	}
	if listenerCfg == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing listener config")
	}

	// using the XForwardedFor* listener config settings to determine how/if
	// X-Forwarded-For are trusted/allowed for an inbound request.
	trustedForwardedFor, remoteAddr, err := listenerutil.TrustedFromXForwardedFor(r, listenerCfg)
	switch {
	case err != nil:
		return "", errors.Wrap(ctx, err, op, errors.WithMsg("failed to determine trusted X-Forwarded-For"))
	case trustedForwardedFor == nil && remoteAddr == nil:
		ip, err := ipFromRequestRemoteAddr(ctx, r)
		if err != nil {
			return "", errors.Wrap(ctx, err, op)
		}
		return ip, nil
	case trustedForwardedFor == nil && remoteAddr != nil:
		// not reachable given listenerutil.TrustedFromXForwardedFor
		// implementation in 11/2021 but that could change in the future, so
		// this case is explicitly handled
		return remoteAddr.Host, nil
	default:
		return trustedForwardedFor.Host, nil
	}
}

func ipFromRequestRemoteAddr(ctx context.Context, r *http.Request) (string, error) {
	const op = "common.ipFromRequestRemoteAddr"
	if strings.ContainsRune(r.RemoteAddr, ':') {
		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err != nil {
			return "", errors.Wrap(ctx, err, op)
		} else {
			return ip, nil
		}
	}
	return r.RemoteAddr, nil
}
