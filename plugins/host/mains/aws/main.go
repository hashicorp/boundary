package main

import (
	"fmt"
	"os"

	awshp "github.com/hashicorp/boundary-plugin-host-aws/plugin"
	hp "github.com/hashicorp/boundary/sdk/plugins/host"
)

func main() {
	if err := hp.ServeHostPlugin(new(awshp.AwsPlugin)); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
