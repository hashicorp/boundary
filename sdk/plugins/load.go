// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package external_plugins

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
)

// CreateHostPlugin takes in a type, parses the various options to look for a
// plugin matching that name, and returns a host plugin client, a cleanup
// function to execute on shutdown of the enclosing program, and an error.
func CreateHostPlugin(ctx context.Context, pluginType string, opt ...Option) (pb.HostPluginServiceClient, func() error, error) {
	raw, cleanup, err := createPlugin(ctx, pluginType, hostServicePluginSetName, opt...)
	if err != nil {
		return nil, cleanup, err
	}

	var ok bool
	hp, ok := raw.(pb.HostPluginServiceClient)
	if !ok {
		return nil, cleanup, fmt.Errorf("error converting rpc storage plugin of type %T to normal wrapper", raw)
	}

	return hp, cleanup, nil
}

// CreateStoragePlugin takes in a type, parses the various options to look for a
// plugin matching that name, and returns a storage plugin client, a cleanup
// function to execute on shutdown of the enclosing program, and an error.
func CreateStoragePlugin(ctx context.Context, pluginType string, opt ...Option) (pb.StoragePluginServiceClient, func() error, error) {
	raw, cleanup, err := createPlugin(ctx, pluginType, storageServicePluginSetName, opt...)
	if err != nil {
		return nil, cleanup, err
	}

	var ok bool
	sp, ok := raw.(pb.StoragePluginServiceClient)
	if !ok {
		return nil, cleanup, fmt.Errorf("error converting rpc storage plugin of type %T to normal wrapper", raw)
	}

	return sp, cleanup, nil
}

func createPlugin(
	ctx context.Context,
	pluginType string,
	pluginSetName string,
	opt ...Option,
) (
	raw any,
	cleanup func() error,
	retErr error,
) {
	defer func() {
		if retErr != nil && cleanup != nil {
			_ = cleanup()
		}
	}()

	pluginType = strings.ToLower(pluginType)

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing plugin options: %w", err)
	}

	// First, scan available plugins, then find the right one to use
	pluginMap, err := pluginutil.BuildPluginMap(
		append(
			opts.withPluginOptions,
			pluginutil.WithPluginClientCreationFunc(
				func(pluginPath string, _ ...pluginutil.Option) (*plugin.Client, error) {
					return NewPluginClient(pluginPath, pluginSetName, WithLogger(opts.withLogger))
				}),
		)...)
	if err != nil {
		return nil, nil, fmt.Errorf("error building plugin map: %w", err)
	}

	// Create the plugin and cleanup func
	plugClient, cleanup, err := pluginutil.CreatePlugin(pluginMap[pluginType], opts.withPluginOptions...)
	if err != nil {
		return nil, cleanup, err
	}

	switch client := plugClient.(type) {
	case plugin.ClientProtocol:
		raw, err = client.Dispense(pluginSetName)
		if err != nil {
			return nil, cleanup, fmt.Errorf("error dispensing %q plugin: %w", pluginSetName, err)
		}
	default:
		return nil, cleanup, fmt.Errorf("unable to understand type %T of raw plugin", raw)
	}

	return raw, cleanup, nil
}
