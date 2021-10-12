package external_host_plugins

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
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
	if len(opts.withHostPluginsSources) == 0 {
		return nil, nil, fmt.Errorf("no host plugins available")
	}

	// First, scan available plugins, then find the right one to use
	pluginMap := map[string]pluginInfo{}
	var plugin pluginInfo
	{
		for _, sourceInfo := range opts.withHostPluginsSources {
			switch {
			case sourceInfo.pluginFs != nil:
				dirs, err := fs.ReadDir(sourceInfo.pluginFs, ".")
				if err != nil {
					return nil, nil, fmt.Errorf("error scanning host plugins: %w", err)
				}
				// Store a match between the config type string and the expected plugin name
				for _, entry := range dirs {
					pluginType := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), sourceInfo.pluginFsPrefix), ".gz")
					if runtime.GOOS == "windows" {
						pluginType = strings.TrimSuffix(pluginType, ".exe")
					}
					pluginMap[pluginType] = pluginInfo{
						containerFs: sourceInfo.pluginFs,
						filename:    entry.Name(),
					}
				}
			case sourceInfo.pluginMap != nil:
				for k, creationFunc := range sourceInfo.pluginMap {
					pluginMap[k] = pluginInfo{creationFunc: creationFunc, filename: k}
				}
			}
		}

		plugin = pluginMap[pluginType]
		if plugin.filename == "" && plugin.creationFunc == nil {
			return nil, nil, fmt.Errorf("unknown host plugin type %q", pluginType)
		}
	}

	// If the source is just a func, execute it and skip ahead; otherwise it's a plugin, so instantiate it
	{
		switch {
		case plugin.creationFunc != nil:
			hp, err = plugin.creationFunc()
			if err != nil {
				return nil, nil, fmt.Errorf("error performing direct instantiation of host plugin with type %q: %w", plugin.filename, err)
			}

		case plugin.containerFs != nil:
			hp, cleanup, err = executeHostPlugin(plugin, opt...)
			if err != nil {
				return nil, cleanup, err
			}
		}
	}

	return hp, cleanup, nil
}

// executeHostPlugin takes in the discovered plugin information and spins out
// the actual binary, returning a client that talks to it.
func executeHostPlugin(plugin pluginInfo, opt ...Option) (pb.HostPluginServiceClient, func() error, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing host plugin options: %w", err)
	}

	// Open and basic validation
	file, err := plugin.containerFs.Open(plugin.filename)
	if err != nil {
		return nil, nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("error discovering host plugin information: %w", err)
	}
	if stat.IsDir() {
		return nil, nil, fmt.Errorf("host plugin is a directory, not a file")
	}

	// Read in plugin bytes
	expLen := stat.Size()
	buf := make([]byte, expLen)
	readLen, err := file.Read(buf)
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("error reading host plugin bytes: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, nil, fmt.Errorf("error closing host plugin file: %w", err)
	}
	if int64(readLen) != expLen {
		return nil, nil, fmt.Errorf("reading host plugin expected %d bytes, read %d", expLen, readLen)
	}

	executedFileName := plugin.filename

	// If it's compressed, uncompress it
	if strings.HasSuffix(plugin.filename, ".gz") {
		executedFileName = strings.TrimSuffix(plugin.filename, ".gz")
		gzipReader, err := gzip.NewReader(bytes.NewReader(buf))
		if err != nil {
			return nil, nil, fmt.Errorf("error creating gzip decompression reader: %w", err)
		}
		uncompBuf := new(bytes.Buffer)
		_, err = uncompBuf.ReadFrom(gzipReader)
		gzipReader.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("error reading gzip compressed data from reader: %w", err)
		}
		buf = uncompBuf.Bytes()
	}

	cleanup := func() error {
		return nil
	}

	// Now, create a temp dir and write out the plugin bytes
	dir := opts.withHostPluginExecutionPath
	if dir == "" {
		tmpDir, err := ioutil.TempDir("", "*")
		if err != nil {
			return nil, nil, fmt.Errorf("error creating tmp dir for kms execution: %w", err)
		}
		cleanup = func() error {
			return os.RemoveAll(tmpDir)
		}
		dir = tmpDir
	}
	pluginPath := filepath.Join(dir, executedFileName)
	if err := ioutil.WriteFile(pluginPath, buf, fs.FileMode(0700)); err != nil {
		return nil, cleanup, fmt.Errorf("error writing out host plugin for execution: %w", err)
	}

	// Execute the plugin
	client, err := NewHostPluginClient(pluginPath, WithLogger(opts.withLogger))
	if err != nil {
		return nil, cleanup, fmt.Errorf("error fetching host plugin client: %w", err)
	}
	origCleanup := cleanup
	cleanup = func() error {
		client.Kill()
		return origCleanup()
	}
	rpcClient, err := client.Client()
	if err != nil {
		return nil, cleanup, fmt.Errorf("error fetching host plugin rpc client: %w", err)
	}

	raw, err := rpcClient.Dispense(hostServicePluginSetName)
	if err != nil {
		return nil, cleanup, fmt.Errorf("error dispensing host plugin: %w", err)
	}

	var ok bool
	hp, ok := raw.(pb.HostPluginServiceClient)
	if !ok {
		return nil, cleanup, fmt.Errorf("error converting rpc host plugin to host plugin interface: %w", err)
	}

	return hp, cleanup, nil
}
