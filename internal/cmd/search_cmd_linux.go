// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"github.com/hashicorp/boundary/internal/clientcache/cmd/cache"
	"github.com/hashicorp/boundary/internal/clientcache/cmd/search"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/wrapper"
	"github.com/mitchellh/cli"
)

func init() {
	extraCommandsFuncs = append(extraCommandsFuncs, func(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
		Commands["cache"] = func() (cli.Command, error) {
			return &cache.CacheCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["cache start"] = func() (cli.Command, error) {
			return &cache.StartCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["cache stop"] = func() (cli.Command, error) {
			return &cache.StopCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["cache add-token"] = func() (cli.Command, error) {
			return &cache.AddTokenCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		Commands["cache status"] = func() (cli.Command, error) {
			return &cache.StatusCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
		// TODO(johanbrandhorst): remove after deprecation period
		Commands["daemon"] = wrapper.WrapForDeprecation(
			func() wrapper.WrappableCommand {
				return &cache.CacheCommand{
					Command: base.NewCommand(ui),
				}
			},
			"daemon",
			"cache",
		)
		// TODO(johanbrandhorst): remove after deprecation period
		Commands["daemon start"] = wrapper.WrapForDeprecation(
			func() wrapper.WrappableCommand {
				return &cache.StartCommand{
					Command: base.NewCommand(ui),
				}
			},
			"daemon",
			"cache",
		)
		// TODO(johanbrandhorst): remove after deprecation period
		Commands["daemon stop"] = wrapper.WrapForDeprecation(
			func() wrapper.WrappableCommand {
				return &cache.StopCommand{
					Command: base.NewCommand(ui),
				}
			},
			"daemon",
			"cache",
		)
		// TODO(johanbrandhorst): remove after deprecation period
		Commands["daemon add-token"] = wrapper.WrapForDeprecation(
			func() wrapper.WrappableCommand {
				return &cache.AddTokenCommand{
					Command: base.NewCommand(ui),
				}
			},
			"daemon",
			"cache",
		)
		// TODO(johanbrandhorst): remove after deprecation period
		Commands["daemon status"] = wrapper.WrapForDeprecation(
			func() wrapper.WrappableCommand {
				return &cache.StatusCommand{
					Command: base.NewCommand(ui),
				}
			},
			"daemon",
			"cache",
		)
		Commands["search"] = func() (cli.Command, error) {
			return &search.SearchCommand{
				Command: base.NewCommand(ui),
			}, nil
		}
	})
}
