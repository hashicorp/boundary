// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sessionrecordingscmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessionrecordings"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*DownloadCommand)(nil)
	_ cli.CommandAutocomplete = (*DownloadCommand)(nil)
)

const (
	castExt = ".cast" // default download file extension (is overridden when an output file is specified)
)

type DownloadCommand struct {
	*base.Command
}

func (c *DownloadCommand) Synopsis() string {
	return wordwrap.WrapString("Download a session recording", base.TermWidth)
}

func (c *DownloadCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary session-recordings download [args]",
		"",
		"  Download a session recording resource. Example:",
		"",
		`    $ boundary session-recordings download -id chr_u6e9wJ8B8H`,
		"",
		"",
	}) + c.Flags().Help()
}

func (c *DownloadCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "id",
		Target: &c.FlagId,
		Usage:  "The id of the session recording resource to download.",
	})
	f.StringVar(&base.StringVar{
		Name:    "output",
		Target:  &c.FlagOutputFile,
		Usage:   "An optional output file for the download. If not provided the recording id will be used with a \".cast\" extension. Use \"-\" for stdout.",
		Aliases: []string{"o"},
	})
	f.BoolVar(&base.BoolVar{
		Name:    "no-clobber",
		Target:  &c.FlagNoClobber,
		Usage:   "An option to stop downloads that would overwrite existing files.",
		Aliases: []string{"nc"},
	})
	return set
}

func (c *DownloadCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *DownloadCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *DownloadCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	switch {
	case c.FlagId == "":
		c.PrintCliError(errors.New("ID must be provided via -id"))
		return base.CommandUserError
	}

	client, err := c.Client()
	if c.WrapperCleanupFunc != nil {
		defer func() {
			if err := c.WrapperCleanupFunc(); err != nil {
				c.PrintCliError(fmt.Errorf("Error cleaning kms wrapper: %w", err))
			}
		}()
	}
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %w", err))
		return base.CommandCliError
	}

	sClient := sessionrecordings.NewClient(client)
	result, err := sClient.Download(c.Context, c.FlagId)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when downloading session recording")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Download error: %w", err))
		return base.CommandCliError
	}

	var outFile *os.File
	switch {
	case c.FlagOutputFile == "-":
		outFile = os.Stdout
	case c.FlagOutputFile != "" && c.FlagNoClobber:
		_, err := os.Stat(c.FlagOutputFile)
		switch {
		case os.IsNotExist(err):
			outFile, err = os.Create(c.FlagOutputFile)
			if err != nil {
				c.PrintCliError(fmt.Errorf("Unable to create download file %q when \"-nc\" was provided: %w", c.FlagOutputFile, err))
				return base.CommandCliError
			}
			defer outFile.Close()
		case err != nil:
			c.PrintCliError(fmt.Errorf("Error trying to check if file %q exists when \"-nc\" was provided: %w", c.FlagOutputFile, err))
			return base.CommandCliError
		default:
			c.PrintCliError(fmt.Errorf("Error trying to overwrite to an existing file %q when \"-nc\" was provided", c.FlagOutputFile))
			return base.CommandCliError
		}
	case c.FlagOutputFile != "":
		outFile, err = os.Create(c.FlagOutputFile)
		if err != nil {
			c.PrintCliError(fmt.Errorf("Unable to create requested download file %q: %w", c.FlagOutputFile, err))
			return base.CommandCliError
		}
		defer outFile.Close()
	default:
		fileName := getNextFileName(c.FlagId)
		outFile, err = os.Create(fileName)
		if err != nil {
			c.PrintCliError(fmt.Errorf("Unable to create download file %q: %w", fileName, err))
			return base.CommandCliError
		}
		defer outFile.Close()
	}

	if _, err := io.Copy(outFile, result); err != nil {
		c.PrintCliError(fmt.Errorf("Error reading download stream: %w", err))
		return base.CommandCliError
	}
	return base.CommandSuccess
}

func getNextFileName(baseName string) string {
	if _, err := os.Stat(baseName + castExt); os.IsNotExist(err) {
		return baseName + castExt
	}
	startIndex := 1
	for {
		fileName := baseName + castExt + "." + strconv.Itoa(startIndex)
		if _, err := os.Stat(fileName); os.IsNotExist(err) {
			return fileName
		}
		startIndex++
	}
}
