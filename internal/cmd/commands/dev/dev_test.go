package dev

import (
	"fmt"
	"sync"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/mitchellh/cli"
)

func TestDev_DatabaseImage(t *testing.T) {
	t.Helper()
	test := []struct {
		args string
		out  int
	}{
		{
			"postgres:latest",
			1,
		},
		{
			"pogrest",
			2,
		},
		{
			"postgres",
			1,
		},
	}

	for _, tt := range test {
		//kms errors if we do not make a new one each time
		wrapper := db.TestWrapper(t)
		wrapper2 := db.TestWrapper(t)
		opts := &controller.TestControllerOpts{
			RootKms:                 wrapper,
			WorkerAuthKms:           wrapper2,
			DisableDatabaseCreation: true,
		}
		tc := controller.NewTestController(t, opts)
		server := tc.Server()
		ui := cli.NewMockUi()
		c := NewCommand(*server, ui)

		args := []string{
			"-database-image=" + tt.args,
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			code := c.Run(args)
			fmt.Println("code")
			t.Log(code)
			wg.Done()
		}()

		tc.Shutdown()
		wg.Wait()
	}

}
