package event

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func Test_NewEventer(t *testing.T) {
	require := require.New(t)

	logger := hclog.New(&hclog.LoggerOptions{
		Name: "test",
	})
	c := EventerConfig{
		ObservationsEnabled: true,
	}
	// with no defined config, it will default to a stdout sink
	e, err := NewEventer(logger, c)
	require.NoError(err)

	m := map[string]interface{}{
		"name": "bar",
		"list": []string{"1", "2"},
	}
	observationEvent, err := NewObservation("Test_NewEventer", WithHeader(m))
	require.NoError(err)

	require.NoError(e.WriteObservation(context.Background(), observationEvent))

}
