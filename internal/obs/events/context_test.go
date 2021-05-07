package event_test

import (
	"context"
	"testing"

	event "github.com/hashicorp/boundary/internal/obs/events"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func Test_WriteInfo(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Name: "test",
	})
	c := event.Config{
		InfoEnabled: true,
		Sinks: []event.SinkConfig{
			// TODO: jimlambrt -> need to refactor the Eventer before this 2nd
			// sink will work.  We need a pipeline for every sink that's configured.
			// {
			// 	Name:       "tmp.txt",
			// 	EventTypes: []event.Type{event.EveryType},
			// 	Format:     event.JSONSinkFormat,
			// 	Path:       "./",
			// 	FileName:   "tmp.txt",
			// },
			{
				Name:       "stdout",
				EventTypes: []event.Type{event.EveryType},
				Format:     event.JSONSinkFormat,
				SinkType:   event.StdoutSink,
			},
		},
	}
	e, err := event.NewEventer(logger, c)
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309"}

	testHdr := map[string]interface{}{
		"name": "bar",
		"list": []string{"1", "2"},
	}

	ctx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	ctx, err = event.NewRequestInfoContext(ctx, info)
	require.NoError(t, err)

	tests := []struct {
		name    string
		header  map[string]interface{}
		details map[string]interface{}
		ctx     context.Context
	}{
		{
			name:   "simple",
			ctx:    ctx,
			header: testHdr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			err := event.WriteInfo(tt.ctx, "Test_WriteInfo", event.WithHeader(tt.header))
			require.NoError(err)
		})
	}

}
