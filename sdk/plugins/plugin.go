// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package external_plugins

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

const (
	hostServicePluginSetName    = "host-plugin"
	storageServicePluginSetName = "storage-plugin"
)

// HandshakeConfig is a shared config that can be used regardless of plugin, to
// avoid having to know type-specific things about each plugin
var HandshakeConfig = plugin.HandshakeConfig{
	MagicCookieKey:   "HASHICORP_BOUNDARY_PLUGIN",
	MagicCookieValue: "boundary-plugin",
}

// ServeHostPlugin is a generic function to start serving a host plugin service as a
// plugin
func ServePlugin(svc any, opt ...Option) error {
	opts, err := getOpts(opt...)
	if err != nil {
		return err
	}

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGHUP)
	go func() {
		for {
			<-signalCh
		}
	}()

	plugins := make(map[string]plugin.Plugin)
	if hostSvc, ok := svc.(pb.HostPluginServiceServer); ok {
		hostServiceServer, err := NewHostPluginServiceServer(hostSvc)
		if err != nil {
			return err
		}
		plugins[hostServicePluginSetName] = hostServiceServer
	}
	if storageSvc, ok := svc.(pb.StoragePluginServiceServer); ok {
		storageServiceServer, err := NewStoragePluginServiceServer(storageSvc)
		if err != nil {
			return err
		}
		plugins[storageServicePluginSetName] = storageServiceServer
	}
	if len(plugins) == 0 {
		return errors.New("no valid plugin server provided")
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: plugins,
		},
		Logger:     opts.withLogger,
		GRPCServer: plugin.DefaultGRPCServer,
	})
	return nil
}

func NewPluginClient(pluginPath, setName string, opt ...Option) (*plugin.Client, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	var set plugin.PluginSet
	switch setName {
	case hostServicePluginSetName:
		set = plugin.PluginSet{hostServicePluginSetName: &hostPlugin{}}
	case storageServicePluginSetName:
		set = plugin.PluginSet{storageServicePluginSetName: &storagePlugin{}}
	}

	return plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: set,
		},
		Cmd: exec.Command(pluginPath),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		Logger:   opts.withLogger,
		AutoMTLS: true,
	}), nil
}

type hostPlugin struct {
	plugin.Plugin

	impl pb.HostPluginServiceServer
}

func NewHostPluginServiceServer(impl pb.HostPluginServiceServer) (*hostPlugin, error) {
	if impl == nil {
		return nil, fmt.Errorf("empty underlying host plugin passed in")
	}
	return &hostPlugin{
		impl: impl,
	}, nil
}

func (h *hostPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterHostPluginServiceServer(s, h.impl)
	return nil
}

func (h *hostPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return pb.NewHostPluginServiceClient(c), nil
}

type storagePlugin struct {
	plugin.Plugin

	impl pb.StoragePluginServiceServer
}

func NewStoragePluginServiceServer(impl pb.StoragePluginServiceServer) (*storagePlugin, error) {
	if impl == nil {
		return nil, fmt.Errorf("empty underlying storage plugin passed in")
	}
	return &storagePlugin{
		impl: impl,
	}, nil
}

func (p *storagePlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterStoragePluginServiceServer(s, p.impl)
	return nil
}

func (p *storagePlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return pb.NewStoragePluginServiceClient(c), nil
}
