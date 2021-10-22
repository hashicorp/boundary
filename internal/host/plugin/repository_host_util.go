package plugin

import (
	"context"
	"sort"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

// hostInfo stores the info we need for figuring out host, set membership,
// and value object differences. It also stores dirty flags to indicate
// whether we need to update value objects or the host itself.
type hostInfo struct {
	h                *Host
	ipsToAdd         []interface{}
	ipsToRemove      []interface{}
	dnsNamesToAdd    []interface{}
	dnsNamesToRemove []interface{}
	dirtyHost        bool
}

func createNewHostMap(ctx context.Context,
	catalog *HostCatalog,
	phs []*plgpb.ListHostsResponseHost,
	currentHostMap map[string]*Host) (map[string]*hostInfo, error) {

	const op = "plugin.createNewHostMap"
	newHostMap := make(map[string]*hostInfo, len(phs))

	var err error
	for _, ph := range phs {
		newHost := NewHost(ctx,
			catalog.GetPublicId(),
			ph.GetExternalId(),
			WithName(ph.GetName()),
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
		switch {
		case currHost == nil,
			currHost.Name != newHost.Name,
			currHost.Description != newHost.Description:
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
				for _, a := range currHostIps {
					if hi.ipsToRemove == nil {
						hi.ipsToRemove = make([]interface{}, 0, len(currHostIps))
					}
					obj, err := host.NewIpAddress(ctx, newHost.PublicId, a)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					hi.ipsToRemove = append(hi.ipsToRemove, obj)
				}

				// Now build up additions
				for _, a := range newHost.GetIpAddresses() {
					if hi.ipsToAdd == nil {
						hi.ipsToAdd = make([]interface{}, 0, len(newHost.GetIpAddresses()))
					}
					obj, err := host.NewIpAddress(ctx, newHost.PublicId, a)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					hi.ipsToAdd = append(hi.ipsToAdd, obj)
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
				for _, a := range currHostDnsNames {
					if hi.dnsNamesToRemove == nil {
						hi.dnsNamesToRemove = make([]interface{}, 0, len(currHostDnsNames))
					}
					obj, err := host.NewDnsName(ctx, newHost.PublicId, a)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					hi.dnsNamesToRemove = append(hi.dnsNamesToRemove, obj)
				}

				// Now build up additions
				for _, a := range newHost.GetDnsNames() {
					if hi.dnsNamesToAdd == nil {
						hi.dnsNamesToAdd = make([]interface{}, 0, len(newHost.GetDnsNames()))
					}
					obj, err := host.NewDnsName(ctx, newHost.PublicId, a)
					if err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					hi.dnsNamesToAdd = append(hi.dnsNamesToAdd, obj)
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
	allSetIds map[string]struct{}) {

	setMembershipsToAdd = make(map[string][]string)    // Map of set id to host ids
	setMembershipsToRemove = make(map[string][]string) // Map of set id to host ids
	allSetIds = make(map[string]struct{})              // Stores the total set IDs we'll need to iterate over

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
			setMembershipsToAdd[setToAdd] = append(setMembershipsToAdd[setToAdd], newHostId)
			allSetIds[setToAdd] = struct{}{}
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
			setMembershipsToRemove[setToRemove] = append(setMembershipsToRemove[setToRemove], currentHostId)
			allSetIds[setToRemove] = struct{}{}
		}
	}

	return
}
