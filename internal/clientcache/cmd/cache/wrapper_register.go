// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/wrapper"
	"github.com/hashicorp/boundary/version"
	"github.com/mitchellh/cli"
)

func init() {
	if err := wrapper.RegisterSuccessfulCommandCallback("clientcache", hook); err != nil {
		panic(err)
	}
}

// hook is the callback that is registered with the wrapper package to be called.
// The daemon is not started and the token is not added to the cache if the flag
// SkipCacheDaemon is set.
func hook(ctx context.Context, baseCmd *base.Command, token string) {
	if baseCmd.FlagSkipCacheDaemon {
		return
	}
	started, err := startDaemon(ctx, baseCmd)
	if err != nil {
		// Failed to start the daemon, but we don't need to tell the user
		// since the function already did
		return
	}
	if !started {
		// If we didn't have to start it, check that the version of the cache
		// is current or newer than the CLI.
		// We don't care if the cache is newer than the CLI, since we don't
		// want to kill a cache started by a newer version of the CLI.
		if !cacheVersionIsCurrentOrNewer(ctx, baseCmd) {
			// If the cache is older than the current version, restart it
			// Ignore errors stopping the daemon since it might have been stopped since
			// we last tried to start the daemon.
			_ = stopDaemon(ctx, baseCmd)
			_, err = startDaemon(ctx, baseCmd)
			if err != nil {
				return
			}
		}
	}

	// Cache successfully started and version verified, add the token to the cache
	addTokenToCache(ctx, baseCmd, token)
}

// startDaemon attempts to start a daemon and returns true if we have attempted to start
// the daemon and either it was successful or it was already running.
func startDaemon(ctx context.Context, baseCmd *base.Command) (started bool, _ error) {
	// Ignore errors related to checking if the process is already running since
	// this can fall back to running the process.
	if dotPath, err := DefaultDotDirectory(ctx); err == nil {
		pidPath := filepath.Join(dotPath, pidFileName)
		if running, _ := pidFileInUse(ctx, pidPath); running != nil {
			// return true since it is already running, no need to run it again.
			return false, nil
		}
	}

	cmdName, err := os.Executable()
	if err != nil {
		baseCmd.UI.Error(fmt.Sprintf("unable to find boundary binary for cache startup: %s", err.Error()))
		return false, err
	}

	var stdErr bytes.Buffer
	cmd := exec.Command(cmdName, "cache", "start", "-background")
	cmd.Stderr = &stdErr

	// We use Run here instead of Start because the command spawns off a subprocess and returns.
	// We do not want to send the request to add a persona to the cache until we know the daemon
	// has started up.
	if err := cmd.Run(); err != nil {
		baseCmd.UI.Error(fmt.Sprintf("unable to start cache: %s", err.Error()))
		return false, err
	}
	return !strings.Contains(stdErr.String(), "already running"), nil
}

// stopDaemon makes a best effort attempt at stopping the cache daemon, if it is running
func stopDaemon(ctx context.Context, baseCmd *base.Command) error {
	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		baseCmd.UI.Error(fmt.Sprintf("cannot find daemon directory: %s", err.Error()))
		return err
	}
	pidPath := filepath.Join(dotPath, pidFileName)
	running, err := pidFileInUse(ctx, pidPath)
	if err != nil {
		baseCmd.UI.Error(fmt.Sprintf("PID file in use: %s", err.Error()))
		return err
	}
	if running == nil {
		return nil
	}

	cmdName, err := os.Executable()
	if err != nil {
		baseCmd.UI.Error(fmt.Sprintf("unable to find boundary binary for cache startup: %s", err.Error()))
		return err
	}
	cmd := exec.Command(cmdName, "cache", "stop")
	if err := cmd.Run(); err != nil {
		baseCmd.UI.Error(fmt.Sprintf("unable to stop cache: %s", err.Error()))
		return err
	}
	return nil
}

// silentUi should not be used in situations where the UI is expected to be
// prompt the user for input.
func silentUi() *cli.BasicUi {
	return &cli.BasicUi{
		Writer:      io.Discard,
		ErrorWriter: io.Discard,
	}
}

// addTokenToCache runs AddTokenCommand with the token used in, or retrieved by
// the wrapped command.
func addTokenToCache(ctx context.Context, baseCmd *base.Command, token string) bool {
	com := AddTokenCommand{Command: base.NewCommand(baseCmd.UI)}
	client, err := baseCmd.Client()
	if err != nil {
		return false
	}
	keyringType, tokName, err := baseCmd.DiscoverKeyringTokenInfo()
	if err != nil && token == "" {
		return false
	}
	if token != "" {
		client.SetToken(token)
	}

	// Since the daemon might have just started, we need to wait until it can
	// respond to our requests
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := waitForDaemon(waitCtx); err != nil {
		// TODO: Print the result of this out into a log in the dot directory
		return false
	}

	// We do not want to print errors out from our background interactions with
	// the daemon so use the silentUi to toss out anything that shouldn't be used
	_, apiErr, err := com.Add(ctx, silentUi(), client, keyringType, tokName)
	return err == nil && apiErr == nil
}

// cacheVersionIsCurrentOrNewer requests the version of the cache from the
// daemon, then compares it to the version of the CLI. If the cache version is
// greater than or equal to the CLI, it returns true. In all other cases, including
// errors, it returns false.
func cacheVersionIsCurrentOrNewer(ctx context.Context, baseCmd *base.Command) bool {
	com := StatusCommand{Command: base.NewCommand(baseCmd.UI)}
	// We do not want to print errors out from our background interactions with
	// the daemon so use the silentUi to toss out anything that shouldn't be used
	_, result, apiErr, err := com.Status(ctx)
	if err != nil || apiErr != nil {
		return false
	}
	cacheVersion := version.FromVersionString(result.Version)
	if cacheVersion == nil {
		return false
	}
	cliVersion := version.Get()

	return cacheVersion.Semver().GreaterThanOrEqual(cliVersion.Semver())
}

// waitForDaemon continually looks for the unix socket until it is found or the
// provided context is done. It returns an error if the unix socket is not found
// before the context is done.
func waitForDaemon(ctx context.Context) error {
	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return err
	}
	timer := time.NewTimer(0)

	addr := daemon.SocketAddress(dotPath)
	_, err = os.Stat(addr.Path)
	for os.IsNotExist(err) {
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
		_, err = os.Stat(addr.Path)
		timer.Reset(10 * time.Millisecond)
	}
	return nil
}
