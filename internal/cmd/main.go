// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/cmd/base"
	colorable "github.com/mattn/go-colorable"
	"github.com/mitchellh/cli"
)

// setupEnv parses args and may replace them and sets some env vars to known
// values based on format options
func setupEnv(args []string) (retArgs []string, format string, outputCurlString bool) {
	// handle the workaround for autocomplete install/uninstall not being exported
	if len(args) == 3 &&
		args[0] == "config" &&
		args[1] == "autocomplete" {
		switch args[2] {
		case "install":
			return []string{"-autocomplete-install"}, "table", false
		case "uninstall":
			return []string{"-autocomplete-uninstall"}, "table", false
		}
	}

	var nextArgFormat bool

	for _, arg := range args {
		if nextArgFormat {
			nextArgFormat = false
			format = arg
			continue
		}

		if arg == "--" {
			break
		}

		if len(args) == 1 &&
			(arg == "-version" ||
				arg == "-v") {
			args = []string{"version"}
			break
		}

		if arg == "-output-curl-string" {
			outputCurlString = true
			continue
		}

		// Parse a given flag here, which overrides the env var
		if strings.HasPrefix(arg, "-format=") {
			format = strings.TrimPrefix(arg, "-format=")
		}
		// Handle the case where it is specified without an equal sign
		if arg == "-format" {
			nextArgFormat = true
		}
	}

	envBoundaryCLIFormat := os.Getenv(base.EnvBoundaryCLIFormat)
	// If we did not parse a value, fetch the env var
	if format == "" && envBoundaryCLIFormat != "" {
		format = envBoundaryCLIFormat
	}
	// Lowercase for consistency
	format = strings.ToLower(format)
	if format == "" {
		format = "table"
	}

	return args, format, outputCurlString
}

type RunOptions struct {
	Stdout  io.Writer
	Stderr  io.Writer
	Address string
}

func Run(args []string) int {
	return RunCustom(args, nil)
}

// RunCustom allows passing in a base command template to pass to other
// commands. Currently, this is only used for setting a custom token helper.
func RunCustom(args []string, runOpts *RunOptions) int {
	if runOpts == nil {
		runOpts = &RunOptions{}
	}

	var format string
	var outputCurlString bool
	args, format, outputCurlString = setupEnv(args)

	// Don't use color if disabled
	useColor := true
	if os.Getenv(base.EnvBoundaryCLINoColor) != "" || color.NoColor {
		useColor = false
	}

	if runOpts.Stdout == nil {
		runOpts.Stdout = os.Stdout
	}
	if runOpts.Stderr == nil {
		runOpts.Stderr = os.Stderr
	}

	// Only use colored UI if stdout is a tty, and not disabled
	if useColor && format == "table" {
		if f, ok := runOpts.Stdout.(*os.File); ok {
			runOpts.Stdout = colorable.NewColorable(f)
		}
		if f, ok := runOpts.Stderr.(*os.File); ok {
			runOpts.Stderr = colorable.NewColorable(f)
		}
	} else {
		runOpts.Stdout = colorable.NewNonColorable(runOpts.Stdout)
		runOpts.Stderr = colorable.NewNonColorable(runOpts.Stderr)
	}

	uiErrWriter := runOpts.Stderr
	if outputCurlString {
		uiErrWriter = ioutil.Discard
	}

	ui := &base.BoundaryUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader:      bufio.NewReader(os.Stdin),
				Writer:      runOpts.Stdout,
				ErrorWriter: uiErrWriter,
			},
		},
		Format: format,
	}

	serverCmdUi := &base.BoundaryUI{
		Ui: &cli.ColoredUi{
			ErrorColor: cli.UiColorRed,
			WarnColor:  cli.UiColorYellow,
			Ui: &cli.BasicUi{
				Reader: bufio.NewReader(os.Stdin),
				Writer: runOpts.Stdout,
			},
		},
		Format: format,
	}

	switch format {
	case "table", "json":
	default:
		ui.Error(fmt.Sprintf("Invalid output format: %s", format))
		return 1
	}

	initCommands(ui, serverCmdUi, runOpts)

	hiddenCommands := []string{"version"}

	cli := &cli.CLI{
		Name:     "boundary",
		Args:     args,
		Commands: Commands,
		HelpFunc: groupedHelpFunc(
			cli.BasicHelpFunc("boundary"),
		),
		HelpWriter:                 runOpts.Stderr,
		HiddenCommands:             hiddenCommands,
		Autocomplete:               true,
		AutocompleteNoDefaultFlags: true,
	}

	exitCode, err := cli.Run()
	if outputCurlString {
		if exitCode == 0 {
			fmt.Fprint(runOpts.Stderr, "Could not generate cURL command\n")
			return 1
		} else {
			if api.LastOutputStringError == nil {
				if exitCode == 127 {
					// Usage, just pass it through
					return exitCode
				}
				fmt.Fprint(runOpts.Stderr, "cURL command not set by API operation; run without -output-curl-string to see the generated error\n")
				return exitCode
			}
			if !strings.Contains(api.LastOutputStringError.Error(), api.ErrOutputStringRequest) {
				runOpts.Stdout.Write([]byte(fmt.Sprintf("Error creating request string: %s\n", api.LastOutputStringError.Error())))
				return 1
			}
			runOpts.Stdout.Write([]byte(fmt.Sprintf("%s\n", api.LastOutputStringError.CurlString())))
			return 0
		}
	} else if err != nil {
		fmt.Fprintf(runOpts.Stderr, "Error executing CLI: %s\n", err.Error())
		return 1
	}

	return exitCode
}

func groupedHelpFunc(f cli.HelpFunc) cli.HelpFunc {
	return func(commands map[string]cli.CommandFactory) string {
		var b bytes.Buffer
		tw := tabwriter.NewWriter(&b, 0, 2, 6, ' ', 0)

		fmt.Fprintf(tw, "Usage: boundary <command> [args]\n")

		otherCommands := make([]string, 0, len(commands))
		for k := range commands {
			otherCommands = append(otherCommands, k)
		}
		sort.Strings(otherCommands)

		fmt.Fprintf(tw, "\n")
		fmt.Fprintf(tw, "Commands:\n")
		for _, v := range otherCommands {
			printCommand(tw, v, commands[v])
		}

		tw.Flush()

		return strings.TrimSpace(b.String())
	}
}

func printCommand(w io.Writer, name string, cmdFn cli.CommandFactory) {
	cmd, err := cmdFn()
	if err != nil {
		panic(fmt.Sprintf("failed to load %q command: %s", name, err))
	}
	fmt.Fprintf(w, "    %s\t%s\n", name, cmd.Synopsis())
}
