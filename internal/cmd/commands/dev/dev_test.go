package dev

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/mitchellh/cli"
)

func TestDev_DatabaseImage(t *testing.T) {
	t.Helper()
	test := []struct {
		name string
		args string
		out  int
	}{
		{
			"repo and tag",
			"postgres:latest",
			0,
		},
		{
			"typo",
			"pogrest",
			3,
		},
		{
			"repo",
			"postgres",
			0,
		},
	}

	for _, tt := range test {
		opts := &controller.TestControllerOpts{
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
		var code int

		go func() {
			code = c.Run(args)
			assert.Equal(t, tt.out, code, "did not receive expected exit code", tt.name)
			t.Log(ui.ErrorWriter.String())
			wg.Done()
		}()

		server.DestroyDevDatabase()
		tc.Shutdown()
		wg.Wait()
	}

}
