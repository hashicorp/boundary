package external_host_plugins

import (
	"context"
	"fmt"
	"os/exec"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

const (
	hostServicePluginSetName = "host-plugin"
)

// HandshakeConfig is a shared config that can be used regardless of plugin, to
// avoid having to know type-specific things about each plugin
var HandshakeConfig = plugin.HandshakeConfig{
	MagicCookieKey:   "HASHICORP_BOUNDARY_HOST_PLUGIN",
	MagicCookieValue: hostServicePluginSetName,
}

// ServeHostPlugin is a generic function to start serving a host plugin service as a
// plugin
func ServeHostPlugin(svc pb.HostPluginServiceServer, opt ...Option) error {
	opts, err := getOpts(opt...)
	if err != nil {
		return err
	}
	hostServiceServer, err := NewHostPluginServiceServer(svc)
	if err != nil {
		return err
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {hostServicePluginSetName: hostServiceServer},
		},
		Logger:     opts.withLogger,
		GRPCServer: plugin.DefaultGRPCServer,
	})
	return nil
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

func NewHostPluginClient(pluginPath string, opt ...Option) (*plugin.Client, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}
	hostServiceClient := &hostPlugin{}

	return plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {hostServicePluginSetName: hostServiceClient},
		},
		Cmd: exec.Command(pluginPath),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		Logger:   opts.withLogger,
		AutoMTLS: true,
	}), nil
}

func (h *hostPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterHostPluginServiceServer(s, h.impl)
	return nil
}

func (h *hostPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return pb.NewHostPluginServiceClient(c), nil
}
