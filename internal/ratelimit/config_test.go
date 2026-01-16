// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/go-rate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigsLimits(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		configs Configs
		want    []rate.Limit
		wantErr error
	}{
		{
			"empty",
			Configs{},
			func() []rate.Limit {
				limits := make([]rate.Limit, 0, len(resource.Map)*len(action.Map))
				for _, res := range resource.Map {
					switch res {
					case resource.Unknown, resource.All, resource.Controller:
						continue
					}
					validActions, err := action.ActionSetForResource(res)
					require.NoError(t, err)
					for a := range validActions {
						switch a {
						case action.Unknown, action.All:
							continue
						case action.List:
							limits = append(
								limits,
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerTotal,
									MaxRequests: DefaultInTotalListRequestLimit,
									Period:      DefaultListPeriod,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerIPAddress,
									MaxRequests: DefaultIpAddressListRequestLimit,
									Period:      DefaultListPeriod,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerAuthToken,
									MaxRequests: DefaultAuthTokenListRequestLimit,
									Period:      DefaultListPeriod,
								},
							)
						default:
							limits = append(
								limits,
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerTotal,
									MaxRequests: DefaultInTotalRequestLimit,
									Period:      DefaultPeriod,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerIPAddress,
									MaxRequests: DefaultIpAddressRequestLimit,
									Period:      DefaultPeriod,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerAuthToken,
									MaxRequests: DefaultAuthTokenRequestLimit,
									Period:      DefaultPeriod,
								},
							)
						}
					}
				}
				return limits
			}(),
			nil,
		},
		{
			"single-config-all-resources-all-actions",
			Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     20,
					Period:    time.Minute * 5,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "ip-address",
					Limit:     10,
					Period:    time.Minute * 5,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "auth-token",
					Limit:     5,
					Period:    time.Minute * 5,
				},
			},
			func() []rate.Limit {
				limits := make([]rate.Limit, 0, len(resource.Map)*len(action.Map))
				for _, res := range resource.Map {
					switch res {
					case resource.Unknown, resource.All, resource.Controller:
						continue
					}
					validActions, err := action.ActionSetForResource(res)
					require.NoError(t, err)
					for a := range validActions {
						switch a {
						case action.Unknown, action.All:
							continue
						default:
							limits = append(
								limits,
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerTotal,
									MaxRequests: 20,
									Period:      time.Minute * 5,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerIPAddress,
									MaxRequests: 10,
									Period:      time.Minute * 5,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerAuthToken,
									MaxRequests: 5,
									Period:      time.Minute * 5,
								},
							)
						}
					}
				}
				return limits
			}(),
			nil,
		},
		{
			"broad-config-with-specific-override",
			Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     20,
					Period:    time.Minute * 5,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "ip-address",
					Limit:     20,
					Period:    time.Minute * 5,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "auth-token",
					Limit:     20,
					Period:    time.Minute * 5,
				},
				{
					Resources: []string{"target"},
					Actions:   []string{"list"},
					Per:       "total",
					Limit:     10,
					Period:    time.Minute,
				},
				{
					Resources: []string{"target"},
					Actions:   []string{"list"},
					Per:       "ip-address",
					Limit:     5,
					Period:    time.Minute,
				},
				{
					Resources: []string{"target"},
					Actions:   []string{"list"},
					Per:       "auth-token",
					Limit:     1,
					Period:    time.Minute,
				},
			},
			func() []rate.Limit {
				limits := make([]rate.Limit, 0, len(resource.Map)*len(action.Map))
				for _, res := range resource.Map {
					switch res {
					case resource.Unknown, resource.All, resource.Controller:
						continue
					}
					validActions, err := action.ActionSetForResource(res)
					require.NoError(t, err)
					for a := range validActions {
						switch a {
						case action.Unknown, action.All:
							continue
						case action.List:
							if res == resource.Target {
								limits = append(
									limits,
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerTotal,
										MaxRequests: 10,
										Period:      time.Minute,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerIPAddress,
										MaxRequests: 5,
										Period:      time.Minute,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerAuthToken,
										MaxRequests: 1,
										Period:      time.Minute,
									},
								)
								continue
							}
							fallthrough
						default:
							limits = append(
								limits,
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerTotal,
									MaxRequests: 20,
									Period:      time.Minute * 5,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerIPAddress,
									MaxRequests: 20,
									Period:      time.Minute * 5,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerAuthToken,
									MaxRequests: 20,
									Period:      time.Minute * 5,
								},
							)
						}
					}
				}
				return limits
			}(),
			nil,
		},
		{
			"multiple-resources",
			Configs{
				{
					Resources: []string{"target", "session"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     10,
					Period:    time.Minute,
				},
				{
					Resources: []string{"target", "session"},
					Actions:   []string{"*"},
					Per:       "ip-address",
					Limit:     5,
					Period:    time.Minute,
				},
				{
					Resources: []string{"target", "session"},
					Actions:   []string{"*"},
					Per:       "auth-token",
					Limit:     1,
					Period:    time.Minute,
				},
			},
			func() []rate.Limit {
				limits := make([]rate.Limit, 0, len(resource.Map)*len(action.Map))
				for _, res := range resource.Map {
					switch res {
					case resource.Unknown, resource.All, resource.Controller:
						continue
					case resource.Target, resource.Session:
						validActions, err := action.ActionSetForResource(res)
						require.NoError(t, err)
						for a := range validActions {
							switch a {
							case action.Unknown, action.All:
								continue
							default:
								limits = append(
									limits,
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerTotal,
										MaxRequests: 10,
										Period:      time.Minute,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerIPAddress,
										MaxRequests: 5,
										Period:      time.Minute,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerAuthToken,
										MaxRequests: 1,
										Period:      time.Minute,
									},
								)
							}
						}
					default:
						validActions, err := action.ActionSetForResource(res)
						require.NoError(t, err)
						for a := range validActions {
							switch a {
							case action.Unknown, action.All:
								continue
							case action.List:
								limits = append(
									limits,
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerTotal,
										MaxRequests: DefaultInTotalListRequestLimit,
										Period:      DefaultListPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerIPAddress,
										MaxRequests: DefaultIpAddressListRequestLimit,
										Period:      DefaultListPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerAuthToken,
										MaxRequests: DefaultAuthTokenListRequestLimit,
										Period:      DefaultListPeriod,
									},
								)
							default:
								limits = append(
									limits,
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerTotal,
										MaxRequests: DefaultInTotalRequestLimit,
										Period:      DefaultPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerIPAddress,
										MaxRequests: DefaultIpAddressRequestLimit,
										Period:      DefaultPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerAuthToken,
										MaxRequests: DefaultAuthTokenRequestLimit,
										Period:      DefaultPeriod,
									},
								)
							}
						}
					}
				}
				return limits
			}(),
			nil,
		},
		{
			"multiple-actions",
			Configs{
				{
					Resources: []string{"target", "session"},
					Actions:   []string{"list", "read"},
					Per:       "total",
					Limit:     10,
					Period:    time.Minute,
				},
				{
					Resources: []string{"target", "session"},
					Actions:   []string{"list", "read"},
					Per:       "ip-address",
					Limit:     5,
					Period:    time.Minute,
				},
				{
					Resources: []string{"target", "session"},
					Actions:   []string{"list", "read"},
					Per:       "auth-token",
					Limit:     1,
					Period:    time.Minute,
				},
			},
			func() []rate.Limit {
				limits := make([]rate.Limit, 0, len(resource.Map)*len(action.Map))
				for _, res := range resource.Map {
					switch res {
					case resource.Unknown, resource.All, resource.Controller:
						continue
					case resource.Target, resource.Session:
						validActions, err := action.ActionSetForResource(res)
						require.NoError(t, err)
						for a := range validActions {
							switch a {
							case action.Unknown, action.All:
								continue
							case action.List, action.Read:
								limits = append(
									limits,
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerTotal,
										MaxRequests: 10,
										Period:      time.Minute,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerIPAddress,
										MaxRequests: 5,
										Period:      time.Minute,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerAuthToken,
										MaxRequests: 1,
										Period:      time.Minute,
									},
								)
							default:
								limits = append(
									limits,
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerTotal,
										MaxRequests: DefaultInTotalRequestLimit,
										Period:      DefaultPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerIPAddress,
										MaxRequests: DefaultIpAddressRequestLimit,
										Period:      DefaultPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerAuthToken,
										MaxRequests: DefaultAuthTokenRequestLimit,
										Period:      DefaultPeriod,
									},
								)
							}
						}
					default:
						validActions, err := action.ActionSetForResource(res)
						require.NoError(t, err)
						for a := range validActions {
							switch a {
							case action.Unknown, action.All:
								continue
							case action.List:
								limits = append(
									limits,
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerTotal,
										MaxRequests: DefaultInTotalListRequestLimit,
										Period:      DefaultListPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerIPAddress,
										MaxRequests: DefaultIpAddressListRequestLimit,
										Period:      DefaultListPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerAuthToken,
										MaxRequests: DefaultAuthTokenListRequestLimit,
										Period:      DefaultListPeriod,
									},
								)
							default:
								limits = append(
									limits,
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerTotal,
										MaxRequests: DefaultInTotalRequestLimit,
										Period:      DefaultPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerIPAddress,
										MaxRequests: DefaultIpAddressRequestLimit,
										Period:      DefaultPeriod,
									},
									&rate.Limited{
										Resource:    res.String(),
										Action:      a.String(),
										Per:         rate.LimitPerAuthToken,
										MaxRequests: DefaultAuthTokenRequestLimit,
										Period:      DefaultPeriod,
									},
								)
							}
						}
					}
				}
				return limits
			}(),
			nil,
		},
		{
			"order-matters",
			Configs{
				// This one is overridden by the second config that is more broad.
				{
					Resources: []string{"target", "session"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     10,
					Period:    time.Minute,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     20,
					Period:    time.Minute * 5,
				},
			},
			func() []rate.Limit {
				limits := make([]rate.Limit, 0, len(resource.Map)*len(action.Map))
				for _, res := range resource.Map {
					switch res {
					case resource.Unknown, resource.All, resource.Controller:
						continue
					}
					validActions, err := action.ActionSetForResource(res)
					require.NoError(t, err)
					for a := range validActions {
						switch a {
						case action.Unknown, action.All:
							continue
						case action.List:
							limits = append(
								limits,
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerTotal,
									MaxRequests: 20,
									Period:      time.Minute * 5,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerIPAddress,
									MaxRequests: DefaultIpAddressListRequestLimit,
									Period:      DefaultListPeriod,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerAuthToken,
									MaxRequests: DefaultAuthTokenListRequestLimit,
									Period:      DefaultListPeriod,
								},
							)
						default:
							limits = append(
								limits,
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerTotal,
									MaxRequests: 20,
									Period:      time.Minute * 5,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerIPAddress,
									MaxRequests: DefaultIpAddressRequestLimit,
									Period:      DefaultPeriod,
								},
								&rate.Limited{
									Resource:    res.String(),
									Action:      a.String(),
									Per:         rate.LimitPerAuthToken,
									MaxRequests: DefaultAuthTokenRequestLimit,
									Period:      DefaultPeriod,
								},
							)
						}
					}
				}
				return limits
			}(),
			nil,
		},
		{
			"no-limits",
			Configs{
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "total",
					Unlimited: true,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "ip-address",
					Unlimited: true,
				},
				{
					Resources: []string{"*"},
					Actions:   []string{"*"},
					Per:       "auth-token",
					Unlimited: true,
				},
			},
			func() []rate.Limit {
				limits := make([]rate.Limit, 0, len(resource.Map)*len(action.Map))
				for _, res := range resource.Map {
					switch res {
					case resource.Unknown, resource.All, resource.Controller:
						continue
					}
					validActions, err := action.ActionSetForResource(res)
					require.NoError(t, err)
					for a := range validActions {
						switch a {
						case action.Unknown, action.All:
							continue
						default:
							limits = append(
								limits,
								&rate.Unlimited{
									Resource: res.String(),
									Action:   a.String(),
									Per:      rate.LimitPerTotal,
								},
								&rate.Unlimited{
									Resource: res.String(),
									Action:   a.String(),
									Per:      rate.LimitPerIPAddress,
								},
								&rate.Unlimited{
									Resource: res.String(),
									Action:   a.String(),
									Per:      rate.LimitPerAuthToken,
								},
							)
						}
					}
				}
				return limits
			}(),
			nil,
		},
		{
			"invalid-resource",
			Configs{
				{
					Resources: []string{"foo"},
					Actions:   []string{"*"},
					Per:       "total",
					Limit:     10,
					Period:    time.Minute,
				},
			},
			nil,
			fmt.Errorf("ratelimit.(Configs).Limits: unknown resource foo: configuration issue: error #5000"),
		},
		{
			"invalid-action-for-resource",
			Configs{
				{
					Resources: []string{"session"},
					Actions:   []string{"authorize-session"},
					Per:       "total",
					Limit:     10,
					Period:    time.Minute,
				},
			},
			nil,
			fmt.Errorf("ratelimit.(Configs).Limits: action authorize-session not valid for resource session: configuration issue: error #5000"),
		},
		{
			"invalid-action",
			Configs{
				{
					Resources: []string{"session"},
					Actions:   []string{"foo"},
					Per:       "total",
					Limit:     10,
					Period:    time.Minute,
				},
			},
			nil,
			fmt.Errorf("ratelimit.(Configs).Limits: action foo not valid for resource session: configuration issue: error #5000"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.configs.Limits(ctx)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestDefaulLimiterMaxQuotas(t *testing.T) {
	var want int

	var endpointCount int
	for _, res := range resource.Map {
		switch res {
		case resource.Unknown, resource.All, resource.Controller:
			continue
		}

		actions, err := action.ActionSetForResource(res)
		require.NoError(t, err)
		endpointCount += len(actions)
	}
	want = endpointCount*2000 + endpointCount

	got := DefaultLimiterMaxQuotas()
	assert.Equal(t, want, got)
}
