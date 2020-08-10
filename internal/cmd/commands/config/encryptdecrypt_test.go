package config

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
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
		{
			encrypt: true,
			config:  configEncryptPath,
			exp:     "",
		},
		{
			encrypt: false,
			config:  configDecryptPath,
			exp:     configEncryptPath,
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("Test encrypt %v", c.encrypt), func(t *testing.T) {

			var b bytes.Buffer

			ui := &cli.BasicUi{
				Reader:      bufio.NewReader(os.Stdin),
				Writer:      &b,
				ErrorWriter: &b,
			}

			cmd := &EncryptDecryptCommand{
				Command: base.NewCommand(ui),
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
