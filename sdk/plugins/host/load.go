package external_host_plugins

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
)

// NOTE: This package could probably use some reflect based bits to allow
// loading other types of plugins later. That is an exercise left for future
// refactoring, but worth calling out now.

type pluginInfo struct {
	containerFs  fs.FS
	filename     string
	creationFunc func() (pb.HostPluginServiceClient, error)
}

// CreateHostPlugin takes in a type, parses the various options to look for a
// plugin matching that name, and returns a host plugin client, a cleanup
// function to execute on shutdown of the enclosing program, and an error.
func CreateHostPlugin(
	ctx context.Context,
	pluginType string,
	opt ...Option,
) (
	hp pb.HostPluginServiceClient,
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
		return nil, nil, fmt.Errorf("error parsing host plugin options: %w", err)
	}

	// First, scan available plugins, then find the right one to use
	pluginMap, err := pluginutil.BuildPluginMap(
		append(
			opts.withPluginOptions,
			pluginutil.WithPluginClientCreationFunc(
				func(pluginPath string, _ ...pluginutil.Option) (*plugin.Client, error) {
					return NewHostPluginClient(pluginPath, WithLogger(opts.withLogger))
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

	var raw any
	switch client := plugClient.(type) {
	case plugin.ClientProtocol:
		raw, err = client.Dispense(hostServicePluginSetName)
		if err != nil {
			return nil, cleanup, fmt.Errorf("error dispensing host plugin: %w", err)
		}
	default:
		return nil, cleanup, fmt.Errorf("unable to understand type %T of raw plugin", raw)
	}

	var ok bool
	hp, ok = raw.(pb.HostPluginServiceClient)
	if !ok {
		return nil, cleanup, fmt.Errorf("error converting rpc host plugin of type %T to normal wrapper", raw)
	}

	return hp, cleanup, nil
}
