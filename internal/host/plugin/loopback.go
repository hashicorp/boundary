package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/mitchellh/mapstructure"
)

const loopbackPluginHostInfoAttrField = "host_info"

var _ plgpb.HostPluginServiceServer = (*loopbackPlugin)(nil)

// loopbackPlugin provides a host plugin with functionality useful for certain
// kinds of testing. It is not (currently) thread-safe.
//
// Over time, if useful, it can be enhanced to do things like handle multiple
// hosts per set.
type loopbackPlugin struct {
	*TestPluginServer

	hostMap map[string]*loopbackPluginHostInfo
}

type loopbackPluginHostInfo struct {
	ExternalId  string   `mapstructure:"external_id"`
	IpAddresses []string `mapstructure:"ip_addresses"`
	DnsNames    []string `mapstructure:"dns_names"`
}

// NewLoopbackPlugin returns a new loopback plugin
func NewLoopbackPlugin() plgpb.HostPluginServiceServer {
	ret := &loopbackPlugin{
		TestPluginServer: new(TestPluginServer),
		hostMap:          make(map[string]*loopbackPluginHostInfo),
	}
	ret.OnCreateCatalogFn = ret.onCreateCatalog
	ret.OnCreateSetFn = ret.onCreateSet
	ret.OnDeleteSetFn = ret.onDeleteSet
	ret.ListHostsFn = ret.listHosts
	return ret
}

func (l *loopbackPlugin) onCreateCatalog(ctx context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
	const op = "plugin.(loopbackPlugin).onCreateCatalog"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "req is nil")
	}
	if cat := req.GetCatalog(); cat != nil {
		if secrets := cat.GetSecrets(); secrets != nil {
			return &plgpb.OnCreateCatalogResponse{
				Persisted: &plgpb.HostCatalogPersisted{
					Data: secrets,
				},
			}, nil
		}
	}
	return nil, nil
}

func (l *loopbackPlugin) onCreateSet(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
	const op = "plugin.(loopbackPlugin).onCreateSet"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "req is nil")
	}
	set := req.GetSet()
	if set == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "set is nil")
	}
	if attrs := set.GetAttributes(); attrs != nil {
		attrsMap := attrs.AsMap()
		if field := attrsMap[loopbackPluginHostInfoAttrField]; field != nil {
			hostInfo := new(loopbackPluginHostInfo)
			if err := mapstructure.Decode(field, hostInfo); err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			l.hostMap[set.GetId()] = hostInfo
		}
	}
	return nil, nil
}

func (l *loopbackPlugin) onDeleteSet(ctx context.Context, req *plgpb.OnDeleteSetRequest) (*plgpb.OnDeleteSetResponse, error) {
	const op = "plugin.(loopbackPlugin).onDeleteSet"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "req is nil")
	}
	set := req.GetCurrentSet()
	if set == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "set is nil")
	}
	delete(l.hostMap, set.GetId())
	return nil, nil
}

func (l *loopbackPlugin) listHosts(ctx context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
	const op = "plugin.(loopbackPlugin).listHosts"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "req is nil")
	}
	resp := new(plgpb.ListHostsResponse)
	for _, set := range req.GetSets() {
		hostInfo := l.hostMap[set.GetId()]
		if hostInfo == nil {
			continue
		}
		resp.Hosts = append(resp.Hosts, &plgpb.ListHostsResponseHost{
			ExternalId:  hostInfo.ExternalId,
			IpAddresses: hostInfo.IpAddresses,
		})
	}
	return resp, nil
}
