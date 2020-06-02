package config

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
)

const (
	configEncryptPath = "./fixtures/configEncrypt.hcl"
	configDecryptPath = "./fixtures/configDecrypt.hcl"
)

func TestEncryptDecrypt(t *testing.T) {

	cases := []struct {
		encrypt bool
		config  string
		exp     string
	}{
		{encrypt: true,
			config: configEncryptPath,
			exp:    ""},
		{encrypt: false,
			config: configDecryptPath,
			exp:    configEncryptPath},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("Test encrypt %v", c.encrypt), func(t *testing.T) {

			var b bytes.Buffer

			cmd := &EncryptDecryptCommand{
				Command: getBaseCommand(&b),
				Encrypt: c.encrypt}

			if err := cmd.Run([]string{c.config}); err != 0 {
				assert.Equal(t, err, 0)
			}

			got := b.String()
			assert.Greater(t, len(got), 0)
			fmt.Printf("%s\n", got)

			// If it's encrypting, then we can assume that it did the right thing since
			// there are many tests on the underlying codebase for that. If it's not
			// encrypting, compare it to the cleartext to verify because we can.
			if !c.encrypt {
				expected, err := ioutil.ReadFile(c.exp)
				assert.NoError(t, err)

				assert.Equal(t, strings.TrimSpace(string(expected)), strings.TrimSpace(string(got)))
			}
		})
	}
}

func getBaseCommand(out *bytes.Buffer) *base.Command {
	ctx, cancel := context.WithCancel(context.Background())

	ret := &base.Command{
		UI: &cli.BasicUi{
			Reader:      bufio.NewReader(os.Stdin),
			Writer:      out,
			ErrorWriter: out,
		},
		ShutdownCh: makeShutdownCh(),
		Context:    ctx,
	}

	go func() {
		<-ret.ShutdownCh
		cancel()
	}()

	return ret
}

func makeShutdownCh() chan struct{} {
	resultCh := make(chan struct{})

	shutdownCh := make(chan os.Signal, 4)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdownCh
		close(resultCh)
	}()
	return resultCh
}
