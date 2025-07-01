// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pluginutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	gp "github.com/hashicorp/go-plugin"
)

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) (*options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}
	return &opts, nil
}

// Option - how Options are passed as arguments
type Option func(*options) error

// pluginSourceInfo contains possibilities for plugin creation -- a map that can
// be used to directly create instances, or an FS that can be used to source
// plugin instances.
type pluginSourceInfo struct {
	pluginMap map[string]InmemCreationFunc

	pluginFs       fs.FS
	pluginFsPrefix string

	pluginFileInfo *PluginFileInfo
}

// options = how options are represented
type options struct {
	withPluginSources            []pluginSourceInfo
	withPluginExecutionDirectory string
	withPluginClientCreationFunc PluginClientCreationFunc
	WithSecureConfig             *gp.SecureConfig
}

func getDefaultOptions() options {
	return options{}
}

// WithPluginsFilesystem provides an fs.FS containing plugins that can be
// executed to provide functionality. This can be specified multiple times; all
// FSes will be scanned. Any conflicts will be resolved later (e.g. in
// BuildPluginsMap, the behavior will be last scanned plugin with the same name
// wins).If there are conflicts, the last one wins, a property shared with
// WithPluginsMap and WithPluginFile). The prefix will be stripped from each
// entry when determining the plugin type.
//
// This doesn't currently support any kind of secure config and is meant for
// cases where you can build up this FS securely. See WithPluginFile for adding
// individual files with checksumming.
func WithPluginsFilesystem(withPrefix string, withPlugins fs.FS) Option {
	return func(o *options) error {
		if withPlugins == nil {
			return errors.New("nil plugin filesystem passed into option")
		}
		o.withPluginSources = append(o.withPluginSources,
			pluginSourceInfo{
				pluginFs:       withPlugins,
				pluginFsPrefix: withPrefix,
			},
		)
		return nil
	}
}

// WithPluginsMap provides a map containing functions that can be called to
// instantiate plugins directly. This can be specified multiple times; all maps
// will be scanned. Any conflicts will be resolved later (e.g. in
// BuildPluginsMap, the behavior will be last scanned plugin with the same name
// wins).If there are conflicts, the last one wins, a property shared with
// WithPluginsFilesystem and WithPluginFile).
func WithPluginsMap(with map[string]InmemCreationFunc) Option {
	return func(o *options) error {
		if len(with) == 0 {
			return errors.New("no entries in plugins map passed into option")
		}
		o.withPluginSources = append(o.withPluginSources,
			pluginSourceInfo{
				pluginMap: with,
			},
		)
		return nil
	}
}

// WithPluginFile provides source information for a file on disk (rather than an
// fs.FS abstraction or an in-memory function). Secure hash info _must_ be
// provided in this case. If there are conflicts with the name, the last one
// wins, a property shared with WithPluginsFilesystem and WithPluginsMap).
func WithPluginFile(with PluginFileInfo) Option {
	return func(o *options) error {
		// Start with validating that the file exists
		switch {
		case with.Name == "":
			return errors.New("plugin file name is empty")
		case with.Path == "":
			return errors.New("plugin file path is empty")
		case len(with.Checksum) == 0:
			return errors.New("plugin file checksum is empty")
		}

		switch with.HashMethod {
		case HashMethodUnspecified:
			with.HashMethod = HashMethodSha2256
		case HashMethodSha2256,
			HashMethodSha2384,
			HashMethodSha2512,
			HashMethodSha3256,
			HashMethodSha3384,
			HashMethodSha3512:
		default:
			return fmt.Errorf("unsupported hash method %q", string(with.HashMethod))
		}
		info, err := os.Stat(with.Path)
		if err != nil {
			return fmt.Errorf("plugin at %q not found on filesystem: %w", with.Path, err)
		}
		if info.IsDir() {
			return fmt.Errorf("plugin at path %q is a directory", with.Path)
		}

		o.withPluginSources = append(o.withPluginSources,
			pluginSourceInfo{
				pluginFileInfo: &with,
			},
		)
		return nil
	}
}

// WithPluginExecutionDirectory allows setting a specific directory for writing
// out and executing plugins; if not set, os.TempDir will be used to create a
// suitable directory
func WithPluginExecutionDirectory(with string) Option {
	return func(o *options) error {
		o.withPluginExecutionDirectory = with
		return nil
	}
}

// WithPluginClientCreationFunc allows passing in the func to use to create a plugin
// client on the host side. Not necessary if only inmem functions are used, but
// required otherwise.
func WithPluginClientCreationFunc(with PluginClientCreationFunc) Option {
	return func(o *options) error {
		o.withPluginClientCreationFunc = with
		return nil
	}
}

// WithSecureConfig allows passing in the go-plugin secure config struct for
// validating a plugin prior to execution. Generally not needed if the plugin is
// being spun out of the binary at runtime.
func WithSecureConfig(with *gp.SecureConfig) Option {
	return func(o *options) error {
		o.WithSecureConfig = with
		return nil
	}
}
