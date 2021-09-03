package testhostplugin

import (
	"context"
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/plugin/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

// testExpectedCatalogAttributes is the expected attributes payload
// for the attributes section for OnCreate and OnUpdate host catalog
// requests.
var testExpectedCatalogAttributes = map[string]interface{}{
	"type": "catalog",
	"foo":  "bar",
}

// testExpectedCatalogAttributesNew is the expected attributes
// payload for the attributes section for OnUpdate and OnDelete host
// catalog requests.
var testExpectedCatalogAttributesNew = map[string]interface{}{
	"type": "catalog",
	"foo":  "baz",
}

// testExpectedSetAttributes is the expected attributes payload for
// the attributes section for OnCreate and OnUpdate host set
// requests.
var testExpectedSetAttributes = map[string]interface{}{
	"type": "set",
	"foo":  "bar",
}

// testExpectedSetAttributesNew is the expected attributes payload
// for the attributes section for OnUpdate and OnDelete host set
// requests.
var testExpectedSetAttributesNew = map[string]interface{}{
	"type": "set",
	"foo":  "baz",
}

// testExpectedPersisted is the expected persisted data for functions
// that take persisted data pre-update. See
// testExpectedPersistedNew for data that's expected to be sent
// back on update and should be expected post-update.
var testExpectedPersisted = map[string]interface{}{
	"secret": "A485613C-2C28-432E-965C-7F3707E6818E",
}

// testExpectedPersistedNew is the expected persisted data
// post-update.
var testExpectedPersistedNew = map[string]interface{}{
	"secret": "617DC271-0531-4BCF-9539-E84D23150AEC",
}

// mapAsStruct returns a structpb.Struct from a
// map[string]interface{}. Errors result in a panic.
func mapAsStruct(m map[string]interface{}) *structpb.Struct {
	out, err := structpb.NewStruct(m)
	if err != nil {
		panic(err)
	}

	return out
}

// TestHostPlugin is an internal plugin used for testing the host
// plugin system.
type TestHostPlugin struct{}

// NewClient returns a HostPluginServiceClient for TestHostPlugin.
func NewClient() proto.HostPluginServiceClient {
	return &TestHostPlugin{}
}

// OnCreateCatalog implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnCreateCatalog(ctx context.Context, in *proto.OnCreateCatalogRequest, _ ...grpc.CallOption) (*proto.OnCreateCatalogResponse, error) {
	const op = "testhostplugin.(TestHostPlugin).OnCreateCatalog"
	cat := in.GetCatalog()
	if cat == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog")
	}

	attrs := cat.GetAttributes()
	if attrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing attributes")
	}

	attrsMap := attrs.AsMap()
	if diff := cmp.Diff(attrsMap, testExpectedCatalogAttributes); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	return &proto.OnCreateCatalogResponse{
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersisted),
		},
	}, nil
}

// OnUpdateCatalog implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnUpdateCatalog(ctx context.Context, in *proto.OnUpdateCatalogRequest, _ ...grpc.CallOption) (*proto.OnUpdateCatalogResponse, error) {
	const op = "testhostplugin.(TestHostPlugin).OnUpdateCatalog"
	currCat := in.GetCurrentCatalog()
	if currCat == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing current catalog")
	}

	newCat := in.GetNewCatalog()
	if newCat == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing new catalog")
	}

	persisted := in.GetPersisted()
	if persisted == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted message")
	}

	persistedData := persisted.GetData()
	if persistedData == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted data")
	}

	currAttrs := currCat.GetAttributes()
	if currAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing current attributes")
	}

	newAttrs := newCat.GetAttributes()
	if currAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing new attributes")
	}

	currAttrsMap := currAttrs.AsMap()
	if diff := cmp.Diff(currAttrsMap, testExpectedCatalogAttributes); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	newAttrsMap := newAttrs.AsMap()
	if diff := cmp.Diff(newAttrsMap, testExpectedCatalogAttributesNew); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	persistedDataMap := persistedData.AsMap()
	if diff := cmp.Diff(persistedDataMap, testExpectedPersisted); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	return &proto.OnUpdateCatalogResponse{
		Persisted: &proto.HostCatalogPersisted{
			Data: mapAsStruct(testExpectedPersistedNew),
		},
	}, nil
}

// OnDeleteCatalog implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnDeleteCatalog(ctx context.Context, in *proto.OnDeleteCatalogRequest, _ ...grpc.CallOption) (*proto.OnDeleteCatalogResponse, error) {
	const op = "testhostplugin.(TestHostPlugin).OnDeleteCatalog"
	cat := in.GetCatalog()
	if cat == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog")
	}

	persisted := in.GetPersisted()
	if persisted == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted data")
	}

	persistedData := persisted.GetData()
	if persistedData == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted data")
	}

	attrs := cat.GetAttributes()
	if attrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing attributes")
	}

	attrsMap := attrs.AsMap()
	if diff := cmp.Diff(attrsMap, testExpectedCatalogAttributesNew); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	persistedDataMap := persistedData.AsMap()
	if diff := cmp.Diff(persistedDataMap, testExpectedPersistedNew); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	return &proto.OnDeleteCatalogResponse{}, nil
}

// OnCreateSet implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnCreateSet(ctx context.Context, in *proto.OnCreateSetRequest, _ ...grpc.CallOption) (*proto.OnCreateSetResponse, error) {
	const op = "testhostplugin.(TestHostPlugin).OnCreateSet"
	cat := in.GetCatalog()
	if cat == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog")
	}

	catAttrs := cat.GetAttributes()
	if catAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog attributes")
	}

	set := in.GetSet()
	if set == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing set")
	}

	setAttrs := set.GetAttributes()
	if setAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing set attributes")
	}

	persisted := in.GetPersisted()
	if persisted == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted message")
	}

	persistedData := persisted.GetData()
	if persistedData == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted data")
	}

	catAttrsMap := catAttrs.AsMap()
	if diff := cmp.Diff(catAttrsMap, testExpectedCatalogAttributes); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	setAttrsMap := setAttrs.AsMap()
	if diff := cmp.Diff(setAttrsMap, testExpectedSetAttributes); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	persistedDataMap := persistedData.AsMap()
	if diff := cmp.Diff(persistedDataMap, testExpectedPersisted); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	return &proto.OnCreateSetResponse{}, nil
}

// OnUpdateSet implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnUpdateSet(ctx context.Context, in *proto.OnUpdateSetRequest, _ ...grpc.CallOption) (*proto.OnUpdateSetResponse, error) {
	const op = "testhostplugin.(TestHostPlugin).OnUpdateSet"
	cat := in.GetCatalog()
	if cat == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog")
	}

	catAttrs := cat.GetAttributes()
	if catAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog attributes")
	}

	currSet := in.GetCurrentSet()
	if currSet == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing current set")
	}

	currSetAttrs := currSet.GetAttributes()
	if currSetAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing current set attributes")
	}

	newSet := in.GetNewSet()
	if newSet == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing new set")
	}

	newSetAttrs := newSet.GetAttributes()
	if newSetAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing new set attributes")
	}

	persisted := in.GetPersisted()
	if persisted == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted message")
	}

	persistedData := persisted.GetData()
	if persistedData == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted data")
	}

	catAttrsMap := catAttrs.AsMap()
	if diff := cmp.Diff(catAttrsMap, testExpectedCatalogAttributes); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	currSetAttrsMap := currSetAttrs.AsMap()
	if diff := cmp.Diff(currSetAttrsMap, testExpectedSetAttributes); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	newSetAttrsMap := newSetAttrs.AsMap()
	if diff := cmp.Diff(newSetAttrsMap, testExpectedSetAttributesNew); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	persistedDataMap := persistedData.AsMap()
	if diff := cmp.Diff(persistedDataMap, testExpectedPersisted); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	return &proto.OnUpdateSetResponse{}, nil
}

// OnDeleteSet implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) OnDeleteSet(ctx context.Context, in *proto.OnDeleteSetRequest, opts ...grpc.CallOption) (*proto.OnDeleteSetResponse, error) {
	const op = "testhostplugin.(TestHostPlugin).OnDeleteSet"
	cat := in.GetCatalog()
	if cat == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog")
	}

	catAttrs := cat.GetAttributes()
	if catAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog attributes")
	}

	set := in.GetSet()
	if set == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing set")
	}

	setAttrs := set.GetAttributes()
	if setAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing set attributes")
	}

	persisted := in.GetPersisted()
	if persisted == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted message")
	}

	persistedData := persisted.GetData()
	if persistedData == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted data")
	}

	catAttrsMap := catAttrs.AsMap()
	if diff := cmp.Diff(catAttrsMap, testExpectedCatalogAttributes); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	setAttrsMap := setAttrs.AsMap()
	if diff := cmp.Diff(setAttrsMap, testExpectedSetAttributesNew); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	persistedDataMap := persistedData.AsMap()
	if diff := cmp.Diff(persistedDataMap, testExpectedPersisted); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	return &proto.OnDeleteSetResponse{}, nil
}

// ListHosts implements HostPluginServiceClient for TestHostPlugin.
func (p *TestHostPlugin) ListHosts(ctx context.Context, in *proto.ListHostsRequest, opts ...grpc.CallOption) (*proto.ListHostsResponse, error) {
	const op = "testhostplugin.(TestHostPlugin).OnDeleteSet"
	cat := in.GetCatalog()
	if cat == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog")
	}

	catAttrs := cat.GetAttributes()
	if catAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing catalog attributes")
	}

	sets := in.GetSets()
	if sets == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing sets")
	}

	if len(sets) != 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("incorrect number of sets provided, want=1, got=%d", len(sets)))
	}

	set := sets[0]
	if set == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "set is nil")
	}

	setAttrs := set.GetAttributes()
	if setAttrs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing set attributes")
	}

	persisted := in.GetPersisted()
	if persisted == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted message")
	}

	persistedData := persisted.GetData()
	if persistedData == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing persisted data")
	}

	catAttrsMap := catAttrs.AsMap()
	if diff := cmp.Diff(catAttrsMap, testExpectedCatalogAttributes); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	setAttrsMap := setAttrs.AsMap()
	if diff := cmp.Diff(setAttrsMap, testExpectedSetAttributes); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	persistedDataMap := persistedData.AsMap()
	if diff := cmp.Diff(persistedDataMap, testExpectedPersisted); diff != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, diff)
	}

	return &proto.ListHostsResponse{
		Hosts: []*proto.ListHostsResponseHost{
			&proto.ListHostsResponseHost{
				ExternalId: "host-foo",
				Address:    "10.0.0.100",
				Attributes: mapAsStruct(map[string]interface{}{
					"id": "foo",
				}),
			},
			&proto.ListHostsResponseHost{
				ExternalId: "host-bar",
				Address:    "10.0.0.101",
				Attributes: mapAsStruct(map[string]interface{}{
					"id": "bar",
				}),
			},
		},
	}, nil
}
