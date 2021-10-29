package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithName", func(t *testing.T) {
		opts := getOpts(WithName("test"))
		assert.Equal(t, "test", opts.withName)
	})
	t.Run("WithPluginId", func(t *testing.T) {
		opts := getOpts(withPluginId("test"))
		assert.Equal(t, "test", opts.withPluginId)
	})
	t.Run("WithDescription", func(t *testing.T) {
		opts := getOpts(WithDescription("test desc"))
		assert.Equal(t, "test desc", opts.withDescription)
	})
	t.Run("WithLimit", func(t *testing.T) {
		opts := getOpts(WithLimit(5))
		assert.Equal(t, 5, opts.withLimit)
	})
	t.Run("WithPreferredEndpoints", func(t *testing.T) {
		opts := getOpts(WithPreferredEndpoints([]string{"foo"}))
		assert.EqualValues(t, []string{"foo"}, opts.withPreferredEndpoints)
	})
	t.Run("WithDnsNames", func(t *testing.T) {
		opts := getOpts(withDnsNames([]string{"foo"}))
		assert.EqualValues(t, []string{"foo"}, opts.withDnsNames)
	})
	t.Run("WithIpAddresses", func(t *testing.T) {
		opts := getOpts(withIpAddresses([]string{"foo"}))
		assert.EqualValues(t, []string{"foo"}, opts.withIpAddresses)
	})
}
