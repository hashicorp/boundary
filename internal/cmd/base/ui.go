package base

import (
	"os"

	"github.com/mitchellh/cli"
	"golang.org/x/crypto/ssh/terminal"
)

type BoundaryUI struct {
	cli.Ui
	Format string
}

var TermWidth uint = 80

func init() {
	width, _, err := terminal.GetSize(int(os.Stdin.Fd()))
	if err == nil {
		TermWidth = uint(width)
	}
}
