package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/cmd/commands/config"
	"github.com/hashicorp/watchtower/internal/cmd/commands/controller"
	"github.com/hashicorp/watchtower/internal/cmd/commands/dev"
	"github.com/hashicorp/watchtower/internal/cmd/commands/hosts"
	"github.com/hashicorp/watchtower/internal/cmd/commands/scopes"
	"github.com/hashicorp/watchtower/internal/cmd/commands/worker"

	"github.com/mitchellh/cli"
)

// Commands is the mapping of all the available commands.
var Commands map[string]cli.CommandFactory

func initCommands(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
	getBaseCommand := func() *base.Command {
		ctx, cancel := context.WithCancel(context.Background())
		ret := &base.Command{
			UI:         ui,
			ShutdownCh: MakeShutdownCh(),
			Context:    ctx,
		}

		go func() {
			<-ret.ShutdownCh
			cancel()
		}()

		return ret
	}

	Commands = map[string]cli.CommandFactory{
		"controller": func() (cli.Command, error) {
			return &controller.Command{
				Server: base.NewServer(&base.Command{
					UI:         serverCmdUi,
					ShutdownCh: MakeShutdownCh(),
				}),
				SighupCh:  MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"worker": func() (cli.Command, error) {
			return &worker.Command{
				Server: base.NewServer(&base.Command{
					UI:         serverCmdUi,
					ShutdownCh: MakeShutdownCh(),
				}),
				SighupCh:  MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"dev": func() (cli.Command, error) {
			return &dev.Command{
				Server: base.NewServer(&base.Command{
					UI:         serverCmdUi,
					ShutdownCh: MakeShutdownCh(),
				}),
				SighupCh:  MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"hosts create": func() (cli.Command, error) {
			return &hosts.CreateCommand{
				Command: getBaseCommand(),
			}, nil
		},
		"projects create": func() (cli.Command, error) {
			return &scopes.CreateProjectCommand{
				Command: getBaseCommand(),
			}, nil
		},
		"projects read": func() (cli.Command, error) {
			return &scopes.ReadProjectCommand{
				Command: getBaseCommand(),
			}, nil
		},
		"config": func() (cli.Command, error) {
			return &config.Command{
				Command: getBaseCommand(),
			}, nil
		},
		"config encrypt": func() (cli.Command, error) {
			return &config.EncryptDecryptCommand{
				Command: getBaseCommand(),
				Encrypt: true,
			}, nil
		},
		"config decrypt": func() (cli.Command, error) {
			return &config.EncryptDecryptCommand{
				Command: getBaseCommand(),
			}, nil
		},
	}
}

// MakeShutdownCh returns a channel that can be used for shutdown
// notifications for commands. This channel will send a message for every
// SIGINT or SIGTERM received.
func MakeShutdownCh() chan struct{} {
	resultCh := make(chan struct{})

	shutdownCh := make(chan os.Signal, 4)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdownCh
		close(resultCh)
	}()
	return resultCh
}

// MakeSighupCh returns a channel that can be used for SIGHUP
// reloading. This channel will send a message for every
// SIGHUP received.
func MakeSighupCh() chan struct{} {
	resultCh := make(chan struct{})

	signalCh := make(chan os.Signal, 4)
	signal.Notify(signalCh, syscall.SIGHUP)
	go func() {
		for {
			<-signalCh
			resultCh <- struct{}{}
		}
	}()
	return resultCh
}
