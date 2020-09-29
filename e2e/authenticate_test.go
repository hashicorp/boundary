// +build integration

package e2e

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticate(t *testing.T) {
	t.Run(boundary+" "+"authenticate", func(t *testing.T) {
		assert.NotEmpty(t, login(t, tcLoginName, tcPassword, tcPAUM), "must be able to authenticate with default username and password")
	})
}
