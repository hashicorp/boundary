package main

import (
	"fmt"
	"os"

	azhp "github.com/hashicorp/boundary-plugin-host-azure/plugin"
	hp "github.com/hashicorp/boundary/plugins/host"
	"github.com/hashicorp/go-hclog"
)

func main() {
	if err := hp.ServePlugin(new(azhp.AzurePlugin), hp.WithLogger(hclog.NewNullLogger())); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
