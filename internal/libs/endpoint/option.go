// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package endpoint

import (
	"fmt"
	"net"
	"strings"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(&opts); err != nil {
			return options{}, err
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments
type Option func(*options) error

// options = how options are represented
type options struct {
	withIpAddrs  []string
	withDnsNames []string
	withMatchers []matcher
}

func getDefaultOptions() options {
	return options{}
}

// WithIpAddrs contains IP addresses to add into the endpoint possibilities.
// If an IP cannot be parsed, this function will error.
func WithIpAddrs(with []string) Option {
	return func(o *options) error {
		for _, addr := range with {
			ip := net.ParseIP(addr)
			if ip == nil {
				return fmt.Errorf("input '%s' is not parseable as an ip address", addr)
			}
			o.withIpAddrs = append(o.withIpAddrs, addr)
		}
		return nil
	}
}

// WithDnsNames contains DNS names to add into the endpoint possibilities
func WithDnsNames(with []string) Option {
	return func(o *options) error {
		o.withDnsNames = with
		return nil
	}
}

// WithPreferenceOrder contains the preference order specification. If one of
// the preferences cannot be parsed, this function will error. Internally it
// builds up a set of matchers.
func WithPreferenceOrder(with []string) Option {
	return func(o *options) error {
		for _, input := range with {
			var m matcher
			switch {
			case strings.HasPrefix(input, "cidr:"):
				// Make sure ParseCIDR won't choke on a bare address
				cidr := strings.TrimPrefix(input, "cidr:")
				if !strings.Contains(cidr, "/") {
					// See if it seems like an IPv6 address vs. IPv4; colons are
					// a good way to check this
					if strings.Contains(cidr, ":") {
						cidr = fmt.Sprintf("%s/128", cidr)
					} else {
						cidr = fmt.Sprintf("%s/32", cidr)
					}
				}
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					return fmt.Errorf("error parsing cidr %s: %w", cidr, err)
				}
				m = cidrMatcher{
					ipNet: ipNet,
				}

			case strings.HasPrefix(input, "dns:"):
				pattern := strings.TrimPrefix(input, "dns:")
				if pattern == "" {
					return fmt.Errorf("empty dns pattern provided")
				}
				m = dnsMatcher{
					pattern: pattern,
				}

			default:
				return fmt.Errorf("preference string %q is not supported", input)
			}
			if m != nil {
				o.withMatchers = append(o.withMatchers, m)
			}
		}
		return nil
	}
}
