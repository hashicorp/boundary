package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/hashicorp/watchtower/internal/cmd/commands/authenticate"
	"github.com/hashicorp/watchtower/internal/cmd/commands/config"
	"github.com/hashicorp/watchtower/internal/cmd/commands/controller"
	"github.com/hashicorp/watchtower/internal/cmd/commands/dev"
	"github.com/hashicorp/watchtower/internal/cmd/commands/hosts"
	"github.com/hashicorp/watchtower/internal/cmd/commands/roles"
	"github.com/hashicorp/watchtower/internal/cmd/commands/scopes"
	"github.com/hashicorp/watchtower/internal/cmd/commands/worker"

	"github.com/mitchellh/cli"
)

// Commands is the mapping of all the available commands.
var Commands map[string]cli.CommandFactory

func initCommands(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
	Commands = map[string]cli.CommandFactory{
		"controller": func() (cli.Command, error) {
			return &controller.Command{
				Server: base.NewServer(&base.Command{
					UI:         serverCmdUi,
					ShutdownCh: base.MakeShutdownCh(),
				}),
				SighupCh:  MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"worker": func() (cli.Command, error) {
			return &worker.Command{
				Server: base.NewServer(&base.Command{
					UI:         serverCmdUi,
					ShutdownCh: base.MakeShutdownCh(),
				}),
				SighupCh:  MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"dev": func() (cli.Command, error) {
			return &dev.Command{
				Server: base.NewServer(&base.Command{
					UI:         serverCmdUi,
					ShutdownCh: base.MakeShutdownCh(),
				}),
				SighupCh:  MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"hosts create": func() (cli.Command, error) {
			return &hosts.CreateCommand{
				Command: base.NewCommand(ui),
			}, nil
		},
		"projects create": func() (cli.Command, error) {
			return &scopes.CreateProjectCommand{
				Command: base.NewCommand(ui),
			}, nil
		},
		"projects read": func() (cli.Command, error) {
			return &scopes.ReadProjectCommand{
				Command: base.NewCommand(ui),
			}, nil
		},
		"config": func() (cli.Command, error) {
			return &config.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"config encrypt": func() (cli.Command, error) {
			return &config.EncryptDecryptCommand{
				Command: base.NewCommand(ui),
				Encrypt: true,
			}, nil
		},
		"config decrypt": func() (cli.Command, error) {
			return &config.EncryptDecryptCommand{
				Command: base.NewCommand(ui),
			}, nil
		},
		"authenticate": func() (cli.Command, error) {
			return &authenticate.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"authenticate password": func() (cli.Command, error) {
			return &authenticate.PasswordCommand{
				Command: base.NewCommand(ui),
			}, nil
		},
		"roles": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"roles create": func() (cli.Command, error) {
			return &roles.CRUDLCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"roles update": func() (cli.Command, error) {
			return &roles.CRUDLCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"roles read": func() (cli.Command, error) {
			return &roles.CRUDLCommand{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"roles delete": func() (cli.Command, error) {
			return &roles.CRUDLCommand{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"roles list": func() (cli.Command, error) {
			return &roles.CRUDLCommand{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
	}
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
