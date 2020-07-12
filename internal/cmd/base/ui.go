package base

import "github.com/mitchellh/cli"

type WatchtowerUI struct {
	cli.Ui
	Format string
}
