package plugin

import (
	"context"
	"fmt"

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

	hostMap map[string][]*loopbackPluginHostInfo
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
		hostMap:          make(map[string][]*loopbackPluginHostInfo),
	}
	ret.OnCreateCatalogFn = ret.onCreateCatalog
	ret.OnUpdateCatalogFn = ret.onUpdateCatalog
	ret.OnCreateSetFn = ret.onCreateSet
	ret.OnUpdateSetFn = ret.onUpdateSet
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
					Secrets: secrets,
				},
			}, nil
		}
	}
	return &plgpb.OnCreateCatalogResponse{}, nil
}

func (l *loopbackPlugin) onUpdateCatalog(ctx context.Context, req *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error) {
	const op = "plugin.(loopbackPlugin).onUpdateCatalog"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "req is nil")
	}
	if cat := req.GetNewCatalog(); cat != nil {
		if secrets := cat.GetSecrets(); secrets != nil {
			return &plgpb.OnUpdateCatalogResponse{
				Persisted: &plgpb.HostCatalogPersisted{
					Secrets: secrets,
				},
			}, nil
		}
	}
	return &plgpb.OnUpdateCatalogResponse{}, nil
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
			switch t := field.(type) {
			case []any:
				for _, h := range t {
					hostInfo := new(loopbackPluginHostInfo)
					if err := mapstructure.Decode(h, hostInfo); err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					l.hostMap[set.GetId()] = append(l.hostMap[set.GetId()], hostInfo)
				}
			case map[string]any:
				hostInfo := new(loopbackPluginHostInfo)
				if err := mapstructure.Decode(t, hostInfo); err != nil {
					return nil, errors.Wrap(ctx, err, op)
				}
				l.hostMap[set.GetId()] = append(l.hostMap[set.GetId()], hostInfo)
			default:
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown host info type %T", t))
			}
		}
	}
	return &plgpb.OnCreateSetResponse{}, nil
}

func (l *loopbackPlugin) onUpdateSet(ctx context.Context, req *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error) {
	const op = "plugin.(loopbackPlugin).onCreateSet"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "req is nil")
	}
	set := req.GetNewSet()
	if set == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "set is nil")
	}
	var hosts []*loopbackPluginHostInfo
	if attrs := set.GetAttributes(); attrs != nil {
		attrsMap := attrs.AsMap()
		if field := attrsMap[loopbackPluginHostInfoAttrField]; field != nil {
			switch t := field.(type) {
			case []any:
				for _, h := range t {
					hostInfo := new(loopbackPluginHostInfo)
					if err := mapstructure.Decode(h, hostInfo); err != nil {
						return nil, errors.Wrap(ctx, err, op)
					}
					hosts = append(hosts, hostInfo)
				}
			case map[string]any:
				hostInfo := new(loopbackPluginHostInfo)
				if err := mapstructure.Decode(t, hostInfo); err != nil {
					return nil, errors.Wrap(ctx, err, op)
				}
				hosts = append(hosts, hostInfo)
			default:
				return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown host info type %T", t))
			}
		}
	}
	if hosts != nil {
		l.hostMap[set.GetId()] = hosts
	}
	return &plgpb.OnUpdateSetResponse{}, nil
}

func (l *loopbackPlugin) onDeleteSet(ctx context.Context, req *plgpb.OnDeleteSetRequest) (*plgpb.OnDeleteSetResponse, error) {
	const op = "plugin.(loopbackPlugin).onDeleteSet"
	if req == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "req is nil")
	}
	set := req.GetSet()
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
		hostInfos := l.hostMap[set.GetId()]
		if len(hostInfos) == 0 {
			continue
		}
		for _, host := range hostInfos {
			resp.Hosts = append(resp.Hosts, &plgpb.ListHostsResponseHost{
				SetIds:      []string{set.GetId()},
				ExternalId:  host.ExternalId,
				IpAddresses: host.IpAddresses,
				DnsNames:    host.DnsNames,
			})
		}
	}
	return resp, nil
}
