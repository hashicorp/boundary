// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"reflect"
	"sort"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

// valueToInterfaceMap is a map that has a function to convert values into a
// slice
type valueToInterfaceMap map[string]any

func (m valueToInterfaceMap) toSlice() any {
	switch {
	case m == nil:
		return nil
	case len(m) == 0:
		return make([]any, 0)
	default:
		var valueType reflect.Type
		existingValues := make([]any, 0, len(m))
		for _, value := range m {
			valueType = reflect.TypeOf(value) // Assume all values are the same type
			existingValues = append(existingValues, value)
		}
		// Create a slice of the concrete type
		sliceType := reflect.SliceOf(valueType)
		sliceValue := reflect.MakeSlice(sliceType, len(m), len(m))
		for i := 0; i < len(m); i++ {
			sliceValue.Index(i).Set(reflect.ValueOf(existingValues[i]))
		}
		return sliceValue.Interface()
	}
}

// hostInfo stores the info we need for figuring out host, set membership,
// and value object differences. It also stores dirty flags to indicate
// whether we need to update value objects or the host itself.
type hostInfo struct {
	h                *Host
	ipsToAdd         valueToInterfaceMap
	ipsToRemove      valueToInterfaceMap
	dnsNamesToAdd    valueToInterfaceMap
	dnsNamesToRemove valueToInterfaceMap
	dirtyHost        bool
}

func createNewHostMap(ctx context.Context,
	catalog *HostCatalog,
	phs []*plgpb.ListHostsResponseHost,
	currentHostMap map[string]*Host) (map[string]*hostInfo, error,
) {
	const op = "plugin.createNewHostMap"
	newHostMap := make(map[string]*hostInfo, len(phs))

	var err error
	for _, ph := range phs {
		newHost := NewHost(ctx,
			catalog.GetPublicId(),
			ph.GetExternalId(),
			WithName(ph.GetName()),
			WithExternalName(ph.GetExternalName()),
			WithDescription(ph.GetDescription()),
			withIpAddresses(ph.GetIpAddresses()),
			withDnsNames(ph.GetDnsNames()),
			withPluginId(catalog.GetPluginId()))
		newHost.PublicId, err = newHostId(ctx, catalog.GetPublicId(), ph.GetExternalId())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		newHost.SetIds = ph.SetIds
		hi := &hostInfo{
			h: newHost,
		}
		newHostMap[newHost.PublicId] = hi

		// Check if the host is dirty; that is, we need to perform an upsert
		// operation. If the host isn't dirty, we have nothing to do. Note
		// that we don't check every value exhaustively; for instance, we
		// assume catalog ID and external ID don't change because if they do
		// the public ID will be different as well.
		currHost := currentHostMap[newHost.PublicId]
		if currHost != nil {
			hi.h.Version = currHost.Version
		}

		switch {
		case currHost == nil,
			currHost.Name != newHost.Name,
			currHost.Description != newHost.Description,
			currHost.ExternalName != newHost.ExternalName:
			hi.dirtyHost = true
		}

		// Get the current set of host IPs/DNS names for comparison. These
		// will be in sorted order since ordering is kept in the database
		// and they will have been sorted before insertion.
		var currHostIps []string
		var currHostDnsNames []string
		if currHost != nil {
			currHostIps = currHost.IpAddresses
			currHostDnsNames = currHost.DnsNames
		}

		// Sort these here before comparison. We always use a priority order
		// based on the behavior of sort.Strings so that we can check for
		// equivalency.
		sort.Strings(newHost.IpAddresses)
		sort.Strings(newHost.DnsNames)

		// IPs
		{
			switch {
			case strutil.EquivalentSlices(currHostIps, newHost.GetIpAddresses()):
				// Nothing to do...don't remove or add anything

			default:
				// No match, so we need to remove the old ones and add the new

				// First, build up removals
				for _, ip := range currHostIps {
					if hi.ipsToRemove == nil {
						hi.ipsToRemove = make(valueToInterfaceMap, len(currHostIps))
					}
					obj, err := host.NewIpAddress(ctx, newHost.PublicId, ip)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					hi.ipsToRemove[ip] = obj
				}

				// Now build up additions
				for _, ip := range newHost.GetIpAddresses() {
					// If it's in ipsToRemove we found it on the current host;
					// finding it again here means the host still has it, so
					// simply do no change.
					if hi.ipsToRemove != nil && hi.ipsToRemove[ip] != nil {
						delete(hi.ipsToRemove, ip)
						if len(hi.ipsToRemove) == 0 {
							hi.ipsToRemove = nil
						}
						continue
					}
					if hi.ipsToAdd == nil {
						hi.ipsToAdd = make(valueToInterfaceMap, len(newHost.GetIpAddresses()))
					}
					obj, err := host.NewIpAddress(ctx, newHost.PublicId, ip)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					hi.ipsToAdd[ip] = obj
				}
			}
		}

		// DNS names
		{
			switch {
			case strutil.EquivalentSlices(currHostDnsNames, newHost.GetDnsNames()):
				// Nothing to do...don't remove or add anything

			default:
				// No match, so we need to remove the old ones and add the new

				// First, build up removals
				for _, name := range currHostDnsNames {
					if hi.dnsNamesToRemove == nil {
						hi.dnsNamesToRemove = make(valueToInterfaceMap, len(currHostDnsNames))
					}
					obj, err := host.NewDnsName(ctx, newHost.PublicId, name)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					hi.dnsNamesToRemove[name] = obj
				}

				// Now build up additions
				for _, name := range newHost.GetDnsNames() {
					// If it's in dnsNamesToRemove we found it on the current
					// host; finding it again here means the host still has it,
					// so simply do no change.
					if hi.dnsNamesToRemove != nil && hi.dnsNamesToRemove[name] != nil {
						delete(hi.dnsNamesToRemove, name)
						if len(hi.dnsNamesToRemove) == 0 {
							hi.dnsNamesToRemove = nil
						}
						continue
					}
					if hi.dnsNamesToAdd == nil {
						hi.dnsNamesToAdd = make(valueToInterfaceMap, len(newHost.GetDnsNames()))
					}
					obj, err := host.NewDnsName(ctx, newHost.PublicId, name)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					hi.dnsNamesToAdd[name] = obj
				}
			}
		}
	}

	return newHostMap, nil
}

func getSetChanges(
	currentHostMap map[string]*Host,
	newHostMap map[string]*hostInfo) (
	setMembershipsToAdd, setMembershipsToRemove map[string][]string,
) {
	// First, find sets that hosts should be added to: hosts that are new or
	// have new set IDs returned.
	for newHostId, newHost := range newHostMap {
		var setsToAdd []string
		currentHost, ok := currentHostMap[newHostId]
		if !ok {
			// If the host was not known about before now, any sets the host
			// matches will need to be added
			setsToAdd = newHost.h.SetIds
		} else {
			// Otherwise, add to any it doesn't currently match
			for _, setId := range newHost.h.SetIds {
				if !strutil.StrListContains(currentHost.SetIds, setId) {
					setsToAdd = append(setsToAdd, setId)
				}
			}
		}
		// Add to the total set
		for _, setToAdd := range setsToAdd {
			if setMembershipsToAdd == nil {
				setMembershipsToAdd = make(map[string][]string)
			}
			setMembershipsToAdd[setToAdd] = append(setMembershipsToAdd[setToAdd], newHostId)
		}
	}

	// Now, do the inverse: remove hosts from sets that appear there now but no
	// longer have that set ID in their current list.
	for currentHostId, currentHost := range currentHostMap {
		var setsToRemove []string
		newHost, ok := newHostMap[currentHostId]
		if !ok {
			// If the host doesn't even appear now, we obviously want to remove
			// it from all existing set memberships
			setsToRemove = currentHost.SetIds
		} else {
			// Otherwise, remove it from any it doesn't currently have
			for _, setId := range currentHost.SetIds {
				if !strutil.StrListContains(newHost.h.SetIds, setId) {
					setsToRemove = append(setsToRemove, setId)
				}
			}
		}
		// Add to the total set
		for _, setToRemove := range setsToRemove {
			if setMembershipsToRemove == nil {
				setMembershipsToRemove = make(map[string][]string)
			}
			setMembershipsToRemove[setToRemove] = append(setMembershipsToRemove[setToRemove], currentHostId)
		}
	}

	return setMembershipsToAdd, setMembershipsToRemove
}
