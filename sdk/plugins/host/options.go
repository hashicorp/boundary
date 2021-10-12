package external_host_plugins

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-hclog"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...Option) (*options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(opts); err != nil {
			return nil, fmt.Errorf("error running option function: %w", err)
		}
	}
	return opts, nil
}

// Option - a type that wraps an interface for compile-time safety but can
// contain an option for this package or for wrappers implementing this
// interface.
type Option func(*options) error

type options struct {
	withHostPluginsSources      []pluginSourceInfo
	withHostPluginExecutionPath string
	withLogger                  hclog.Logger
}

func getDefaultOptions() *options {
	return &options{}
}

// pluginSourceInfo contains information about plugin sources. Each entry in the
// final slice of withHostPluginsSources will either have the Fs/FsPrefix values
// populated or have the map populated. The former is for loading and executing
// a plugin via go-plugin from the filesystem; the latter is for executing it
// directly in-memory.
type pluginSourceInfo struct {
	pluginMap      map[string]func() (pb.HostPluginServiceClient, error)
	pluginFs       fs.FS
	pluginFsPrefix string
}

// WithLogger allows passing a logger to the plugin library for debugging
func WithLogger(logger hclog.Logger) Option {
	return func(o *options) error {
		o.withLogger = logger
		return nil
	}
}

// WithHostPluginsFilesystem provides an fs.FS containing plugins that can be
// executed to provide Host functionality. This can be specified multiple times;
// all FSes will be scanned. If there are conflicts, the last one wins (this
// property is shared with WithHostPluginsMap). The prefix will be stripped from
// each entry when determining the plugin type.
func WithHostPluginsFilesystem(prefix string, plugins fs.FS) Option {
	return func(o *options) error {
		if plugins == nil {
			return errors.New("nil host plugin filesystem passed into option")
		}
		o.withHostPluginsSources = append(o.withHostPluginsSources,
			pluginSourceInfo{
				pluginFs:       plugins,
				pluginFsPrefix: prefix,
			},
		)
		return nil
	}
}

// WithHostPluginsMap provides a map containing functions that can be called to
// provide implementations of the server. This can be specified multiple times;
// all FSes will be scanned. If there are conflicts, the last one wins (this
// property is shared with WithHostPluginsFilesystem).
func WithHostPluginsMap(plugins map[string]func() (pb.HostPluginServiceClient, error)) Option {
	return func(o *options) error {
		if len(plugins) == 0 {
			return errors.New("no entries in host plugins map passed into option")
		}
		o.withHostPluginsSources = append(o.withHostPluginsSources,
			pluginSourceInfo{
				pluginMap: plugins,
			},
		)
		return nil
	}
}

// WithHostPluginExecutionPath allows setting a specific directory for
// writing out and executing plugins; if not set, os.TempDir will be used
// to create a suitable directory.
func WithHostPluginExecutionPath(dir string) Option {
	return func(o *options) error {
		if dir == "" {
			// We always call this with the option, so if it's not actually set,
			// don't error
			return nil
		}
		fi, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("error while performing stat to validate path %q is a directory: %w", dir, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("given plugin execution path %q is not a directory", dir)
		}
		o.withHostPluginExecutionPath = dir
		return nil
	}
}
