package main_test

import (
	"testing"

	addattributes "github.com/hashicorp/boundary/internal/cmd/addattributes"
	"github.com/stretchr/testify/require"
)

func TestAddAttributes(t *testing.T) {
	err := addattributes.AddAttributes(nil)
	require.NoError(t, err)
}
