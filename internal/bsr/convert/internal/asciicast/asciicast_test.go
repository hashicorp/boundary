// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package asciicast_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/bsr/convert/internal/asciicast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidEventType(t *testing.T) {
	cases := []struct {
		name string
		in   asciicast.EventType
		want bool
	}{
		{
			string(asciicast.Output),
			asciicast.Output,
			true,
		},
		{
			string(asciicast.Input),
			asciicast.Input,
			true,
		},
		{
			string(asciicast.Marker),
			asciicast.Marker,
			true,
		},
		{
			"invalid",
			asciicast.EventType("invalid"),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := asciicast.ValidEventType(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHeaderMarshal(t *testing.T) {
	cases := []struct {
		name    string
		h       *asciicast.Header
		want    []byte
		wantErr error
	}{
		{
			"default",
			asciicast.NewHeader(),
			[]byte(`{"version":2,"width":80,"height":24,"timestamp":-62135596800,"env":{"SHELL":"/bin/bash","TERM":"xterm"}}`),
			nil,
		},
		{
			"layout-time", // https://pkg.go.dev/time#pkg-constants
			&asciicast.Header{
				Version:   asciicast.Version,
				Width:     160,
				Height:    200,
				Timestamp: asciicast.Time(func() time.Time { t, _ := time.Parse(time.Layout, time.Layout); return t }()),
				Env: asciicast.HeaderEnv{
					Shell: "/bin/dash",
					Term:  "st-256color",
				},
			},
			[]byte(`{"version":2,"width":160,"height":200,"timestamp":1136239445,"env":{"SHELL":"/bin/dash","TERM":"st-256color"}}`),
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.h)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func mustEvent(t *testing.T, ty asciicast.EventType, ts float64, data []byte) *asciicast.Event {
	e, err := asciicast.NewEvent(ty, ts, data)
	require.NoError(t, err)
	return e
}

func TestEventMarshal(t *testing.T) {
	cases := []struct {
		name    string
		e       *asciicast.Event
		want    []byte
		wantErr error
	}{
		{
			"echo",
			mustEvent(t, asciicast.Output, 0.1, []byte("echo")),
			[]byte(`[0.1,"o","echo"]`),
			nil,
		},
		{
			"echo-input",
			mustEvent(t, asciicast.Input, 0.1, []byte("echo")),
			[]byte(`[0.1,"i","echo"]`),
			nil,
		},
		{
			"echo-marker",
			mustEvent(t, asciicast.Marker, 0.1, []byte("echo")),
			[]byte(`[0.1,"m","echo"]`),
			nil,
		},
		{
			"time-does-not-round",
			mustEvent(t, asciicast.Output, 0.9999999, []byte("echo")),
			[]byte(`[0.9999999,"o","echo"]`),
			nil,
		},
		{
			"prompt",
			mustEvent(t, asciicast.Output, 0.1, []byte("\x1b[?2004hlocalhost:~$")),
			[]byte(`[0.1,"o","\u001b[?2004hlocalhost:~$"]`),
			nil,
		},
		{
			"new-line",
			mustEvent(t, asciicast.Output, 0.1, []byte("\r\n\x1b[?2004l\r")),
			[]byte(`[0.1,"o","\r\n\u001b[?2004l\r"]`),
			nil,
		},
		{
			"backspace",
			mustEvent(t, asciicast.Output, 0.1, []byte("\b\x1b[K")),
			[]byte(`[0.1,"o","\b\u001b[K"]`),
			nil,
		},
		{
			"tab",
			mustEvent(t, asciicast.Output, 0.1, []byte("\a")),
			[]byte(`[0.1,"o","\u0007"]`),
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.e)
			if tc.wantErr != nil {
				require.EqualError(t, err, tc.wantErr.Error())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
