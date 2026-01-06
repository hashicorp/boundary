// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package endpoint

import (
	"context"
	"net"

	"github.com/hashicorp/boundary/internal/errors"
)

type preferencer struct {
	matchers []matcher
}

// NewPreferencer builds up a preferencer with a set of preference options. This
// can then be used with Choose to select preferences from among a set of IP
// addresses and DNS names.
//
// Supported options: WithPreferenceOrder
func NewPreferencer(ctx context.Context, opt ...Option) (*preferencer, error) {
	const op = "endpoint.NewPreferencer"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	pref := &preferencer{
		matchers: opts.withMatchers,
	}
	return pref, nil
}

// Choose takes in IP addresses and/or DNS names and chooses an endpoint from
// among them, picking one at random if there are no preferences supplied. If
// preferences are specified but none match, the empty string is returned.
// However, if no IP addresses or DNS names are supplied, an error is returned.
//
// Supported options: WithIpAddrs, WithDnsNames
func (p *preferencer) Choose(ctx context.Context, opt ...Option) (string, error) {
	const op = "endpoint.(preferencer).Choose"
	opts, err := getOpts(opt...)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	if len(opts.withIpAddrs)+len(opts.withDnsNames) == 0 {
		return "", errors.New(ctx, errors.InvalidParameter, op, "no ip addresses or dns names passed in")
	}

	switch len(p.matchers) {
	case 0:
		// We have no matchers, so pick a private address if we have one (since
		// those are most likely to be what the user is trying to gain access to
		// via a worker). If we don't have one, pick any IP address, as that's
		// also more likely desired than a DNS name. Otherwise, pick a DNS name.
		// IPv6 follows same rules as 4, but least preferenced.
		nonPrivateIp4s := make([]string, 0, len(opts.withIpAddrs))
		nonPrivateIp6s := make([]string, 0, len(opts.withIpAddrs))
		privateIp6s := make([]string, 0, len(opts.withIpAddrs))

		for _, ipStr := range opts.withIpAddrs {
			ipVal := net.ParseIP(ipStr)
			if ipVal != nil {
				switch ipVal.To4() {
				case nil: // it's v6
					if ipVal.IsPrivate() {
						privateIp6s = append(privateIp6s, ipStr)
					} else {
						nonPrivateIp6s = append(nonPrivateIp6s, ipStr)
					}
				default:
					if ipVal.IsPrivate() {
						// private IPv4 is most highly preferenced, so return it directly
						return ipStr, nil
					}
					nonPrivateIp4s = append(nonPrivateIp4s, ipStr)
				}
			}
		}

		switch {
		case len(nonPrivateIp4s) > 0:
			return nonPrivateIp4s[0], nil

		case len(opts.withDnsNames) > 0:
			return opts.withDnsNames[0], nil

		case len(privateIp6s) > 0:
			return privateIp6s[0], nil

		case len(nonPrivateIp6s) > 0:
			return nonPrivateIp6s[0], nil

		default:
			// We literally have nothing if we get here, so return nothing
			return "", nil
		}

	default:
		for _, m := range p.matchers {
			switch m.(type) {
			case dnsMatcher:
				for _, name := range opts.withDnsNames {
					if m.Match(name) {
						return name, nil
					}
				}
			case cidrMatcher:
				for _, addr := range opts.withIpAddrs {
					if m.Match(addr) {
						return addr, nil
					}
				}
			}
		}
		// Nothing matched. Don't treat it as an error, let the calling function
		// simply ignore the empty result.
		return "", nil
	}
}
