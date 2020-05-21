package config

import (
	"testing"
	"time"

	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/stretchr/testify/assert"
)

func TestDevController(t *testing.T) {
	actual, err := DevController()
	if err != nil {
		t.Fatal(err)
	}

	addr, err := sockaddr.NewIPAddr("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	exp := &Config{
		SharedConfig: &configutil.SharedConfig{
			DisableMlock: true,
			Listeners: []*configutil.Listener{
				{
					Type:                  "tcp",
					Purpose:               []string{"api"},
					TLSDisable:            true,
					ProxyProtocolBehavior: "allow_authorized",
					ProxyProtocolAuthorizedAddrs: []*sockaddr.SockAddrMarshaler{
						{SockAddr: addr},
					},
					CorsEnabled:        true,
					CorsAllowedOrigins: []string{"*"},
				},
				{
					Type:                  "tcp",
					Purpose:               []string{"cluster"},
					TLSDisable:            true,
					ProxyProtocolBehavior: "allow_authorized",
					ProxyProtocolAuthorizedAddrs: []*sockaddr.SockAddrMarshaler{
						{SockAddr: addr},
					},
				},
			},
			Seals: []*configutil.KMS{
				{
					Type:    "aead",
					Purpose: []string{"controller"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
					},
				},
				{
					Type:    "aead",
					Purpose: []string{"worker-auth"},
					Config: map[string]string{
						"aead_type": "aes-gcm",
					},
				},
			},
			Telemetry: &configutil.Telemetry{
				DisableHostname:         true,
				PrometheusRetentionTime: time.Hour * 24,
			},
		},
		DevController: true,
	}

	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig
	exp.Listeners[1].RawConfig = actual.Listeners[1].RawConfig
	exp.Seals[0].Config["key"] = actual.Seals[0].Config["key"]
	exp.Seals[1].Config["key"] = actual.Seals[1].Config["key"]

	assert.Equal(t, exp, actual)
}
