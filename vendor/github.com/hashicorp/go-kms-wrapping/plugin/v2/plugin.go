// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	context "context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	gp "github.com/hashicorp/go-plugin"
	grpc "google.golang.org/grpc"
)

// HandshakeConfig is a shared config that can be used regardless of wrapper, to
// avoid having to know type-specific things about each plugin
var HandshakeConfig = gp.HandshakeConfig{
	MagicCookieKey:   "HASHICORP_GKW_PLUGIN",
	MagicCookieValue: "wrapper",
}

// wrapper embeds Plugin and is used as the top-level
type wrapper struct {
	// Embeding this will disable the netRPC protocol
	gp.NetRPCUnsupportedPlugin

	impl wrapping.Wrapper
}

// ServePlugin is a generic function to start serving a wrapper as a plugin
func ServePlugin(wrapper wrapping.Wrapper, opt ...Option) error {
	opts, err := getOpts(opt...)
	if err != nil {
		return err
	}

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, sighup)
	go func() {
		for {
			<-signalCh
		}
	}()

	wrapServer, err := NewWrapperServer(wrapper)
	if err != nil {
		return err
	}
	gp.Serve(&gp.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]gp.PluginSet{
			1: {"wrapping": wrapServer},
		},
		Logger:     opts.withLogger,
		GRPCServer: gp.DefaultGRPCServer,
	})
	return nil
}

func NewWrapperServer(impl wrapping.Wrapper) (*wrapper, error) {
	if impl == nil {
		return nil, fmt.Errorf("empty underlying wrapper passed in")
	}

	return &wrapper{
		impl: impl,
	}, nil
}

func NewWrapperClient(pluginPath string, opt ...Option) (*gp.Client, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	return gp.NewClient(&gp.ClientConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]gp.PluginSet{
			1: {"wrapping": &wrapper{}},
		},
		Cmd: exec.Command(pluginPath),
		AllowedProtocols: []gp.Protocol{
			gp.ProtocolGRPC,
		},
		Logger:       opts.withLogger,
		AutoMTLS:     true,
		SecureConfig: opts.withSecureConfig,
	}), nil
}

func (w *wrapper) GRPCServer(broker *gp.GRPCBroker, s *grpc.Server) error {
	RegisterWrappingServer(s, &wrapServer{impl: w.impl})
	return nil
}

func (w *wrapper) GRPCClient(ctx context.Context, broker *gp.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &wrapClient{impl: NewWrappingClient(c)}, nil
}
