package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/watchtower/e2e/cli"
)

func TestDevServerStart(t *testing.T) {
	cmd, err := cli.Start("dev")
	if err != nil {
		t.Errorf("err starting in dev mode: '%s'", err.Error())
	}

	go func() {
		if err := cmd.Wait(); err != nil {
			t.Error(err.Error())
		}
	}()

	time.Sleep(3 * time.Second)
	if err := cmd.Process.Kill(); err != nil {
		t.Errorf("error sending kill to dev server: %s", err.Error())
	}
}

func TestAuthenticate(t *testing.T) {
	serverCmd, err := cli.Start("dev")
	if err != nil {
		t.Errorf("err starting in dev mode: %s", err.Error())
	}
	defer serverCmd.Process.Kill()
	time.Sleep(3 * time.Second)

	authCmdOut, err := cli.Run("authenticate", "password", "-name", "test", "-method-id", "am_1234567890")
	if err != nil {
		t.Errorf("err authenticating: %s", err.Error())
	}

	fmt.Printf("%s\n", authCmdOut)

}
