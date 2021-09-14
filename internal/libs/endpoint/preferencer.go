package endpoint

import (
	"context"
	"math/rand"
	"time"

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
		return nil, errors.Wrap(ctx, err, op)
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
		// We have no matchers, so pick one at random
		allAddrs := append(opts.withIpAddrs, opts.withDnsNames...)
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		return allAddrs[rng.Intn(len(allAddrs))], nil

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
