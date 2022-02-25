package main

import (
	"fmt"
	"os"

	azhp "github.com/hashicorp/boundary-plugin-host-azure/plugin"
	hp "github.com/hashicorp/boundary/sdk/plugins/host"
)

func main() {
	if err := hp.ServeHostPlugin(new(azhp.AzurePlugin)); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
