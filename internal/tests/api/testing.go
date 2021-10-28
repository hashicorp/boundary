package api

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CloudEventFromFile will marshal a single cloud event from the provided file
// name
func CloudEventFromFile(t *testing.T, fileName string) *cloudevents.Event {
	t.Helper()
	b, err := ioutil.ReadFile(fileName)
	assert.NoError(t, err)
	got := &cloudevents.Event{}
	err = json.Unmarshal(b, got)
	require.NoErrorf(t, err, "json: %s", string(b))
	return got
}

// GetEventDetails is a testing helper will return the details from the event
// payload for a given messageType (request or response)
func GetEventDetails(t *testing.T, e *cloudevents.Event, messageType string) map[string]interface{} {
	t.Helper()
	require := require.New(t)
	require.NotNil(e)
	require.NotEmpty(messageType)
	data, ok := e.Data.(map[string]interface{})
	if !ok {
		return nil
	}
	msgType, ok := data[messageType].(map[string]interface{})
	if !ok {
		return nil
	}

	details, ok := msgType["details"].(map[string]interface{})
	if !ok {
		return nil
	}
	return details
}

// AssertRedactedValues will assert that the values for the given keys within
// the data have been redacted
func AssertRedactedValues(t *testing.T, data interface{}, keys ...string) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	require.NotNil(data)
	dataMap, ok := data.(map[string]interface{})
	require.Truef(ok, "data must be a map[string]interface{}")

	rMap := make(map[string]bool, len(keys))
	for _, s := range keys {
		rMap[s] = true
	}
	for k, v := range dataMap {
		switch typ := v.(type) {
		case []interface{}:
			for _, s := range typ {
				if _, ok := rMap[k]; ok {
					assert.Equalf(encrypt.RedactedData, s, "expected %s to be redacted and it was set to: %s", k, v)
				} else {
					assert.NotEqualf(encrypt.RedactedData, s, "did not expect %s to be redacted", k)
				}
			}
		default:
			if _, ok := rMap[k]; ok {
				assert.Equalf(encrypt.RedactedData, v, "expected %s to be redacted and it was set to: %s", k, v)
			} else {
				assert.NotEqualf(encrypt.RedactedData, v, "did not expect %s to be redacted", k)
			}
		}
	}
}
