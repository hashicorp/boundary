// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-rate"

	// Imported to register all actions for all resources
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/accounts"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/authtokens"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/billing"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentiallibraries"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentials"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentialstores"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/groups"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/health"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_catalogs"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_sets"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/hosts"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/managed_groups"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/policies"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/roles"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/scopes"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/session_recordings"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/sessions"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/storage_buckets"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/users"
	_ "github.com/hashicorp/boundary/internal/daemon/controller/handlers/workers"
)

// Defaults used when creating default rate.Limits.
const (
	DefaultInTotalRequestLimit       = 30000
	DefaultIpAddressRequestLimit     = 30000
	DefaultAuthTokenRequestLimit     = 3000
	DefaultPeriod                    = time.Second * 30
	DefaultInTotalListRequestLimit   = 1500
	DefaultIpAddressListRequestLimit = 1500
	DefaultAuthTokenListRequestLimit = 150
	DefaultListPeriod                = time.Second * 30
)

// defaultLimiterMaxQuotas is the default maximum number of quotas that
// can be tracked by the rate limiter.
// This is determined at initialization time based on the number of endpoints.
var defaultLimiterMaxQuotas int

var initDefaultLimiterMaxQuotas sync.Once

// DefaultLimiterMaxQuotas returns the default maximum number of quotas that
// can be tracked by the rate limiter.
func DefaultLimiterMaxQuotas() int {
	initDefaultLimiterMaxQuotas.Do(func() {
		// Calculate the default max number of quotas that the rate limiter can
		// store. This is calculated based on the number of endpoints and a
		// static number of quotas per endpoint. This seems like a reasonable
		// way to determine a sane default value. However, it should be noted
		// that this total is shared across all endpoints, and some endpoints
		// will be used more frequently than others.

		const quotasPerInTotal = 1
		const quotasPerIpAddress = 1000
		const quotasPerAuthToken = 1000

		var endpointCount int
		for _, res := range resource.Map {
			switch res {
			case resource.Unknown, resource.All, resource.Controller:
				continue
			}

			actions, err := action.ActionSetForResource(res)
			if err != nil {
				panic(fmt.Sprintf("No actions registered for resource %q", res.String()))
			}
			endpointCount += len(actions)
		}

		defaultLimiterMaxQuotas = (endpointCount * quotasPerInTotal) +
			(endpointCount * quotasPerAuthToken) +
			(endpointCount * quotasPerIpAddress)
	})
	return defaultLimiterMaxQuotas
}

// Config is used to configure rate limits. Each config is used to specify
// the maximum number of requests that can be made in a time period for the
// corresponding resources and actions.
type Config struct {
	Resources []string      `hcl:"resources"`
	Actions   []string      `hcl:"actions"`
	Per       string        `hcl:"per"`
	Limit     int           `hcl:"limit"`
	PeriodHCL string        `hcl:"period"`
	Period    time.Duration `hcl:"-"`
	Unlimited bool          `hcl:"unlimited"`
}

// Configs is an ordered set of Config.
type Configs []*Config

// Equal checks if a set of Configs is equal to another set of Configs.
func (c Configs) Equal(o Configs) bool {
	return reflect.DeepEqual(c, o)
}

// Limits creates a slice of rate.Limit from the Configs. This will enumerate
// every combination of resource+action, defining a Limit for each.
func (c Configs) Limits(ctx context.Context) ([]rate.Limit, error) {
	const op = "ratelimit.(Configs).Limits"

	defaults := make(map[string]rate.Limit, len(resource.Map)*len(action.Map))

	allResources := make([]resource.Type, 0, len(resource.Map))
	for _, res := range resource.Map {
		switch res {
		case resource.Unknown, resource.All, resource.Controller:
			continue
		}
		allResources = append(allResources, res)
	}

	for _, res := range allResources {
		validActions, err := action.ActionSetForResource(res)
		if err != nil {
			// This shouldn't be possible, since we should have encountered
			// this error during init and panicked already. If for some reason
			// that was not the case, it seems like a good idea to panic here.
			panic(fmt.Sprintf("No actions registered for resource %q", res.String()))
		}

		for a := range validActions {
			inTotalKey := fmt.Sprintf("%s:%s:%s", res.String(), a.String(), rate.LimitPerTotal)
			authTokenKey := fmt.Sprintf("%s:%s:%s", res.String(), a.String(), rate.LimitPerAuthToken)
			ipAddressKey := fmt.Sprintf("%s:%s:%s", res.String(), a.String(), rate.LimitPerIPAddress)
			switch a {
			case action.List:
				defaults[inTotalKey] = &rate.Limited{
					Resource:    res.String(),
					Action:      a.String(),
					Per:         rate.LimitPerTotal,
					MaxRequests: DefaultInTotalListRequestLimit,
					Period:      DefaultListPeriod,
				}
				defaults[authTokenKey] = &rate.Limited{
					Resource:    res.String(),
					Action:      a.String(),
					Per:         rate.LimitPerAuthToken,
					MaxRequests: DefaultAuthTokenListRequestLimit,
					Period:      DefaultListPeriod,
				}
				defaults[ipAddressKey] = &rate.Limited{
					Resource:    res.String(),
					Action:      a.String(),
					Per:         rate.LimitPerIPAddress,
					MaxRequests: DefaultIpAddressListRequestLimit,
					Period:      DefaultListPeriod,
				}
			default:
				defaults[inTotalKey] = &rate.Limited{
					Resource:    res.String(),
					Action:      a.String(),
					Per:         rate.LimitPerTotal,
					MaxRequests: DefaultInTotalRequestLimit,
					Period:      DefaultPeriod,
				}
				defaults[authTokenKey] = &rate.Limited{
					Resource:    res.String(),
					Action:      a.String(),
					Per:         rate.LimitPerAuthToken,
					MaxRequests: DefaultAuthTokenRequestLimit,
					Period:      DefaultPeriod,
				}
				defaults[ipAddressKey] = &rate.Limited{
					Resource:    res.String(),
					Action:      a.String(),
					Per:         rate.LimitPerIPAddress,
					MaxRequests: DefaultIpAddressRequestLimit,
					Period:      DefaultPeriod,
				}
			}
		}
	}

	for _, cc := range c {
		var resourceSet []resource.Type
		switch {
		case len(cc.Resources) == 1 && cc.Resources[0] == resource.All.String():
			resourceSet = allResources
		default:
			for _, r := range cc.Resources {
				rr, ok := resource.Map[r]
				if !ok {
					return nil, errors.New(ctx, errors.InvalidConfiguration, op, "", errors.WithMsg("unknown resource %s", r))
				}
				resourceSet = append(resourceSet, rr)
			}
		}

		switch {
		case len(cc.Actions) == 1 && cc.Actions[0] == action.All.String():
			for _, res := range resourceSet {
				validActions, err := action.ActionSetForResource(res)
				if err != nil {
					return nil, err
				}
				for a := range validActions {
					key := fmt.Sprintf("%s:%s:%s", res.String(), a.String(), rate.LimitPer(cc.Per))

					switch {
					case cc.Unlimited:
						defaults[key] = &rate.Unlimited{
							Resource: res.String(),
							Action:   a.String(),
							Per:      rate.LimitPer(cc.Per),
						}
					default:
						defaults[key] = &rate.Limited{
							Resource:    res.String(),
							Action:      a.String(),
							Per:         rate.LimitPer(cc.Per),
							MaxRequests: uint64(cc.Limit),
							Period:      cc.Period,
						}
					}
				}
			}
		default:
			for _, res := range resourceSet {
				validActions, err := action.ActionSetForResource(res)
				if err != nil {
					return nil, err
				}
				validActionMap := make(map[string]action.Type, len(validActions))
				for a := range validActions {
					validActionMap[a.String()] = a
				}

				for _, aStr := range cc.Actions {
					a, ok := validActionMap[aStr]
					if !ok {
						return nil, errors.New(ctx, errors.InvalidConfiguration, op, "", errors.WithMsg("action %s not valid for resource %s", aStr, res.String()))
					}
					key := fmt.Sprintf("%s:%s:%s", res.String(), a.String(), rate.LimitPer(cc.Per))

					switch {
					case cc.Unlimited:
						defaults[key] = &rate.Unlimited{
							Resource: res.String(),
							Action:   a.String(),
							Per:      rate.LimitPer(cc.Per),
						}
					default:
						defaults[key] = &rate.Limited{
							Resource:    res.String(),
							Action:      a.String(),
							Per:         rate.LimitPer(cc.Per),
							MaxRequests: uint64(cc.Limit),
							Period:      cc.Period,
						}
					}
				}
			}
		}
	}

	limits := make([]rate.Limit, 0, len(defaults))
	for _, v := range defaults {
		limits = append(limits, v)
	}
	return limits, nil
}
