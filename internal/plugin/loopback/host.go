// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package loopback

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/mitchellh/mapstructure"
)

var _ plgpb.HostPluginServiceServer = (*TestPluginHostServer)(nil)

// TestPluginHostServer provides a host plugin service server where each method can be overwritten for tests.
type TestPluginHostServer struct {
	NormalizeCatalogDataFn func(context.Context, *plgpb.NormalizeCatalogDataRequest) (*plgpb.NormalizeCatalogDataResponse, error)
	OnCreateCatalogFn      func(context.Context, *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error)
	OnUpdateCatalogFn      func(context.Context, *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error)
	OnDeleteCatalogFn      func(context.Context, *plgpb.OnDeleteCatalogRequest) (*plgpb.OnDeleteCatalogResponse, error)
	NormalizeSetDataFn     func(context.Context, *plgpb.NormalizeSetDataRequest) (*plgpb.NormalizeSetDataResponse, error)
	OnCreateSetFn          func(context.Context, *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error)
	OnUpdateSetFn          func(context.Context, *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error)
	OnDeleteSetFn          func(context.Context, *plgpb.OnDeleteSetRequest) (*plgpb.OnDeleteSetResponse, error)
	ListHostsFn            func(context.Context, *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error)
	plgpb.UnimplementedHostPluginServiceServer
}

func (t TestPluginHostServer) NormalizeCatalogData(ctx context.Context, req *plgpb.NormalizeCatalogDataRequest) (*plgpb.NormalizeCatalogDataResponse, error) {
	if t.NormalizeCatalogDataFn == nil {
		return t.UnimplementedHostPluginServiceServer.NormalizeCatalogData(ctx, req)
	}
	return t.NormalizeCatalogDataFn(ctx, req)
}

func (t TestPluginHostServer) OnCreateCatalog(ctx context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
	if t.OnCreateCatalogFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnCreateCatalog(ctx, req)
	}
	return t.OnCreateCatalogFn(ctx, req)
}

func (t TestPluginHostServer) OnUpdateCatalog(ctx context.Context, req *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error) {
	if t.OnUpdateCatalogFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnUpdateCatalog(ctx, req)
	}
	return t.OnUpdateCatalogFn(ctx, req)
}

func (t TestPluginHostServer) OnDeleteCatalog(ctx context.Context, req *plgpb.OnDeleteCatalogRequest) (*plgpb.OnDeleteCatalogResponse, error) {
	if t.OnDeleteCatalogFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnDeleteCatalog(ctx, req)
	}
	return t.OnDeleteCatalogFn(ctx, req)
}

func (t TestPluginHostServer) NormalizeSetData(ctx context.Context, req *plgpb.NormalizeSetDataRequest) (*plgpb.NormalizeSetDataResponse, error) {
	if t.NormalizeSetDataFn == nil {
		return t.UnimplementedHostPluginServiceServer.NormalizeSetData(ctx, req)
	}
	return t.NormalizeSetDataFn(ctx, req)
}

func (t TestPluginHostServer) OnCreateSet(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
	if t.OnCreateSetFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnCreateSet(ctx, req)
	}
	return t.OnCreateSetFn(ctx, req)
}

func (t TestPluginHostServer) OnUpdateSet(ctx context.Context, req *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error) {
	if t.OnUpdateSetFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnUpdateSet(ctx, req)
	}
	return t.OnUpdateSetFn(ctx, req)
}

func (t TestPluginHostServer) OnDeleteSet(ctx context.Context, req *plgpb.OnDeleteSetRequest) (*plgpb.OnDeleteSetResponse, error) {
	if t.OnDeleteSetFn == nil {
		return t.UnimplementedHostPluginServiceServer.OnDeleteSet(ctx, req)
	}
	return t.OnDeleteSetFn(ctx, req)
}

func (t TestPluginHostServer) ListHosts(ctx context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
	if t.ListHostsFn == nil {
		return t.UnimplementedHostPluginServiceServer.ListHosts(ctx, req)
	}
	return t.ListHostsFn(ctx, req)
}

type loopbackPluginHostInfo struct {
	ExternalId  string   `mapstructure:"external_id"`
	IpAddresses []string `mapstructure:"ip_addresses"`
	DnsNames    []string `mapstructure:"dns_names"`
}

// LoopbackHost provides a host plugin with functionality useful for certain
// kinds of testing.
//
// It is not (currently) thread-safe.
//
// Over time, if useful, it can be enhanced to do things like handle multiple
// hosts per set.
type LoopbackHost struct {
	hostMap map[string][]*loopbackPluginHostInfo
}

func (l *LoopbackHost) onCreateCatalog(ctx context.Context, req *plgpb.OnCreateCatalogRequest) (*plgpb.OnCreateCatalogResponse, error) {
	const op = "loopback.(loopbackPlugin).onCreateCatalog"
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

func (l *LoopbackHost) onUpdateCatalog(ctx context.Context, req *plgpb.OnUpdateCatalogRequest) (*plgpb.OnUpdateCatalogResponse, error) {
	const op = "loopback.(loopbackPlugin).onUpdateCatalog"
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

func (l *LoopbackHost) onCreateSet(ctx context.Context, req *plgpb.OnCreateSetRequest) (*plgpb.OnCreateSetResponse, error) {
	const op = "loopback.(loopbackPlugin).onCreateSet"
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

func (l *LoopbackHost) onUpdateSet(ctx context.Context, req *plgpb.OnUpdateSetRequest) (*plgpb.OnUpdateSetResponse, error) {
	const op = "loopback.(loopbackPlugin).onCreateSet"
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

func (l *LoopbackHost) onDeleteSet(ctx context.Context, req *plgpb.OnDeleteSetRequest) (*plgpb.OnDeleteSetResponse, error) {
	const op = "loopback.(loopbackPlugin).onDeleteSet"
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

func (l *LoopbackHost) listHosts(ctx context.Context, req *plgpb.ListHostsRequest) (*plgpb.ListHostsResponse, error) {
	const op = "loopback.(loopbackPlugin).listHosts"
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
