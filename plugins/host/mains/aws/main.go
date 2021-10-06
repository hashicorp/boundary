package main

import (
	"fmt"
	"os"

	awshp "github.com/hashicorp/boundary-plugin-host-aws/plugin"
	hp "github.com/hashicorp/boundary/sdk/plugins/host"
	"github.com/hashicorp/go-hclog"
)

func main() {
	if err := hp.ServeHostPlugin(new(awshp.AwsPlugin), hp.WithLogger(hclog.NewNullLogger())); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
