package cmd

import (
	"os"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/cli"
)

type Formatter interface {
	//Output(ui cli.Ui, secret *api.Secret, data interface{}) error
	Format(data interface{}) ([]byte, error)
}

var Formatters = map[string]Formatter{
	"json":  base.JsonFormatter{},
	"table": base.TableFormatter{},
	"yaml":  base.YamlFormatter{},
	"yml":   base.YamlFormatter{},
}

func Format(ui cli.Ui) string {
	switch ui.(type) {
	case *WatchtowerUI:
		return ui.(*WatchtowerUI).format
	}

	format := os.Getenv(base.EnvWatchtowerCLIFormat)
	if format == "" {
		format = "table"
	}

	return format
}
