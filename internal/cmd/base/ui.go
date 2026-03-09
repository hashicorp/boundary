// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"os"

	"github.com/mitchellh/cli"
	"golang.org/x/term"
)

type BoundaryUI struct {
	cli.Ui
	Format string
}

var TermWidth uint = 80

func init() {
	width, _, err := term.GetSize(int(os.Stdin.Fd()))
	if err == nil {
		TermWidth = uint(width)
	}
}
