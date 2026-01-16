// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/assert"
)

const (
	configEncryptPath            = "./fixtures/config_encrypt.hcl"
	configDecryptPath            = "./fixtures/config_decrypt.hcl"
	configKmsPath                = "./fixtures/config_kms.hcl"
	configExtEncryptPath         = "./fixtures/config_ext_encrypt.hcl"
	configExtEncryptStrippedPath = "./fixtures/config_ext_encrypt_stripped.hcl"
	configExtDecryptPath         = "./fixtures/config_ext_decrypt.hcl"
)

func TestEncryptDecrypt(t *testing.T) {
	cases := []struct {
		f         string
		config    string
		configKms string
		exp       string
		strip     bool
	}{
		{
			f:      "encrypt",
			config: configEncryptPath,
		},
		{
			f:      "decrypt",
			config: configDecryptPath,
			exp:    configEncryptPath,
		},
		{
			f:         "encrypt-ext",
			config:    configExtEncryptPath,
			configKms: configKmsPath,
		},
		{
			f:         "decrypt-ext",
			config:    configExtDecryptPath,
			configKms: configKmsPath,
			exp:       configExtEncryptPath,
		},
		{
			f:         "decrypt-ext-strip",
			config:    configExtDecryptPath,
			configKms: configKmsPath,
			exp:       configExtEncryptStrippedPath,
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("Test encrypt %v", c.f), func(t *testing.T) {
			var b bytes.Buffer

			ui := &cli.BasicUi{
				Reader:      bufio.NewReader(os.Stdin),
				Writer:      &b,
				ErrorWriter: &b,
			}

			cmd := &EncryptDecryptCommand{
				Command: base.NewCommand(ui),
				Func:    c.f,
			}

			args := []string{"-config", c.config}
			if c.configKms != "" {
				args = append(args, "-config-kms", c.configKms)
			}
			if c.strip {
				args = append(args, "-strip")
			}
			if err := cmd.Run(args); err != 0 {
				assert.Equal(t, err, 0)
			}

			got := b.String()
			assert.Greater(t, len(got), 0)
			fmt.Printf("%s\n", got)

			// If it's encrypting, then we can assume that it did the right thing since
			// there are many tests on the underlying codebase for that. If it's not
			// encrypting, compare it to the cleartext to verify because we can.
			if c.f == "decrypt" {
				expected, err := os.ReadFile(c.exp)
				assert.NoError(t, err)

				assert.Equal(t, strings.TrimSpace(string(expected)), strings.TrimSpace(string(got)))
			}
		})
	}
}
