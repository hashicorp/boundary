// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package wrapper

import (
	"context"
	"fmt"
	"os"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	configutil "github.com/hashicorp/go-secure-stdlib/configutil/v2"
	"github.com/hashicorp/go-secure-stdlib/pluginutil/v2"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/hcl"
)

// pluginsConfig is used to pre-parse any plugins stanza
// in the configuration file, so that we can use the correct
// configuration when creating the KMS plugin for reading the
// rest of the config.
type pluginsConfig struct {
	Plugins struct {
		ExecutionDir string `hcl:"execution_dir"`
	} `hcl:"plugins"`
}

func GetWrapperFromPath(ctx context.Context, path, purpose string, opt ...configutil.Option) (wrapping.Wrapper, func() error, error) {
	kmses, err := configutil.LoadConfigKMSes(path)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing config file: %w", err)
	}
	hclBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("Error reading config file: %w", err)
	}
	pluginsConfig, err := parsePluginsConfig(string(hclBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing plugins stanza in config file: %w", err)
	}
	if pluginsConfig.Plugins.ExecutionDir != "" {
		// Note, this is safe to use because configutil.WithPluginOptions invocations
		// are additive with each other.
		opt = append(opt, configutil.WithPluginOptions(pluginutil.WithPluginExecutionDirectory(pluginsConfig.Plugins.ExecutionDir)))
	}

	return getWrapper(ctx, kmses, purpose, opt...)
}

func GetWrapperFromHcl(ctx context.Context, inHcl, purpose string, opt ...configutil.Option) (wrapping.Wrapper, func() error, error) {
	kmses, err := configutil.ParseKMSes(inHcl, configutil.WithMaxKmsBlocks(-1))
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing KMS HCL: %w", err)
	}
	pluginsConfig, err := parsePluginsConfig(inHcl)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing plugins stanza in config file: %w", err)
	}
	if pluginsConfig.Plugins.ExecutionDir != "" {
		// Note, this is safe to use because configutil.WithPluginOptions invocations
		// are additive with each other.
		opt = append(opt, configutil.WithPluginOptions(pluginutil.WithPluginExecutionDirectory(pluginsConfig.Plugins.ExecutionDir)))
	}

	return getWrapper(ctx, kmses, purpose, opt...)
}

func getWrapper(ctx context.Context, kmses []*configutil.KMS, purpose string, opt ...configutil.Option) (wrapping.Wrapper, func() error, error) {
	var kms *configutil.KMS
	for _, v := range kmses {
		if strutil.StrListContains(v.Purpose, purpose) {
			if kms != nil {
				return nil, nil, fmt.Errorf("Only one %q block marked for %q purpose is allowed", "kms", purpose)
			}
			kms = v
		}
	}
	if kms == nil {
		return nil, nil, nil
	}

	wrapper, cleanup, err := configutil.ConfigureWrapper(
		ctx,
		kms,
		nil,
		nil,
		opt...,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("Error configuring kms: %w", err)
	}

	return wrapper, cleanup, nil
}

func parsePluginsConfig(inHcl string) (*pluginsConfig, error) {
	var conf pluginsConfig
	if err := hcl.Decode(&conf, inHcl); err != nil {
		return nil, err
	}
	return &conf, nil
}
