package event_test

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	event "github.com/hashicorp/boundary/internal/observability/events"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WriteObservation(t *testing.T) {

	logger := hclog.New(&hclog.LoggerOptions{
		Name: "test",
	})

	tmpFile, err := ioutil.TempFile("./", "test_writeobservation-observation")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name()) // just to be sure it's gone after all the tests are done.

	tmpErrFile, err := ioutil.TempFile("./", "test_writeobservation-err")
	require.NoError(t, err)
	tmpErrFile.Close()
	defer os.Remove(tmpErrFile.Name()) // just to be sure it's gone after all the tests are done.

	c := event.EventerConfig{
		ObservationsEnabled: true,
		ObservationDelivery: event.Enforced,
		Sinks: []event.SinkConfig{
			{
				Name:       "observation-file-sink",
				EventTypes: []event.Type{event.EveryType},
				Format:     event.JSONSinkFormat,
				Path:       "./",
				FileName:   tmpFile.Name(),
			},
			{
				Name:       "stdout",
				EventTypes: []event.Type{event.EveryType},
				Format:     event.JSONSinkFormat,
				SinkType:   event.StdoutSink,
			},
			{
				Name:       "err-file-sink",
				EventTypes: []event.Type{event.ErrorType},
				Format:     event.JSONSinkFormat,
				Path:       "./",
				FileName:   tmpErrFile.Name(),
			},
		},
	}
	e, err := event.NewEventer(logger, c)
	require.NoError(t, err)

	info := &event.RequestInfo{Id: "867-5309"}

	ctx, err := event.NewEventerContext(context.Background(), e)
	require.NoError(t, err)
	ctx, err = event.NewRequestInfoContext(ctx, info)
	require.NoError(t, err)
	type observationPayload struct {
		header  map[string]interface{}
		details map[string]interface{}
	}
	tests := []struct {
		name                    string
		observationPayload      []observationPayload
		header                  map[string]interface{}
		details                 map[string]interface{}
		ctx                     context.Context
		errSinkFileName         string
		observationSinkFileName string
		wantFileSink            string
	}{
		{
			name: "simple",
			ctx:  ctx,
			observationPayload: []observationPayload{
				{
					header: map[string]interface{}{
						"name": "bar",
					},
				},
				{
					header: map[string]interface{}{
						"list": []string{"1", "2"},
					},
				},
				{
					details: map[string]interface{}{
						"file": "temp-file.txt",
					},
				},
			},
			header: map[string]interface{}{
				"name": "bar",
				"list": []string{"1", "2"},
			},
			details: map[string]interface{}{
				"file": "temp-file.txt",
			},
			errSinkFileName:         tmpErrFile.Name(),
			observationSinkFileName: tmpFile.Name(),
			wantFileSink:            "first",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			for _, p := range tt.observationPayload {
				err := event.WriteObservation(tt.ctx, event.Op(tt.name), event.WithHeader(p.header), event.WithDetails(p.details))
				require.NoError(err)
			}
			require.NoError(event.WriteObservation(tt.ctx, event.Op(tt.name), event.WithFlush()))

			// err := event.WriteObservation(tt.ctx, event.Op(tt.name), event.WithHeader(tt.header), event.WithDetails(tt.details), event.WithFlush())
			// require.NoError(err)

			if tt.observationSinkFileName != "" {
				defer os.Remove(tt.observationSinkFileName)
				b, err := ioutil.ReadFile(tt.observationSinkFileName)
				require.NoError(err)
				gotObservation := &eventJson{}
				err = json.Unmarshal(b, gotObservation)
				require.NoError(err)

				actualJson, err := json.Marshal(gotObservation)
				require.NoError(err)
				wantJson := testObservationJsonFromCtx(t, tt.ctx, event.Op(tt.name), gotObservation, tt.header, tt.details)

				assert.JSONEq(string(wantJson), string(actualJson))
			}

			if tt.errSinkFileName != "" {
				defer os.Remove(tt.errSinkFileName)
				b, err := ioutil.ReadFile(tt.errSinkFileName)
				require.NoError(err)
				assert.Equal(0, len(b))
			}
		})
	}

}

func testObservationJsonFromCtx(t *testing.T, ctx context.Context, caller event.Op, got *eventJson, hdr, details map[string]interface{}) []byte {
	t.Helper()
	require := require.New(t)

	reqInfo, ok := ctx.Value(event.RequestInfoKey).(*event.RequestInfo)
	require.Truef(ok, "missing reqInfo in ctx")

	j := eventJson{
		CreatedAt: got.CreatedAt,
		EventType: string(event.ObservationType),
		Payload: map[string]interface{}{
			"id": got.Payload["id"].(string),
			"header": map[string]interface{}{
				"op":           string(caller),
				"request_info": reqInfo,
			},
		},
	}
	if hdr != nil {
		h := j.Payload["header"].(map[string]interface{})
		for k, v := range hdr {
			h[k] = v
		}
	}
	if details != nil {
		d := got.Payload["details"].([]interface{})[0].(map[string]interface{})
		j.Payload["details"] = []struct {
			CreatedAt string                 `json:"created_at"`
			Type      string                 `json:"type"`
			Payload   map[string]interface{} `json:"payload"`
		}{
			{
				CreatedAt: d["created_at"].(string),
				Type:      d["type"].(string),
				Payload:   details,
			},
		}
	}
	b, err := json.Marshal(j)
	require.NoError(err)
	return b
}

type eventJson struct {
	CreatedAt string                 `json:"created_at"`
	EventType string                 `json:"event_type"`
	Payload   map[string]interface{} `json:"payload"`
}
