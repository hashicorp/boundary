package config

import (
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/shared-secure-libs/configutil"
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
					Purpose: []string{"root"},
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
				PrometheusRetentionTime: 24 * time.Hour,
				UsageGaugePeriod:        10 * time.Minute,
				MaximumGaugeCardinality: 500,
			},
		},
		Controller: &Controller{
			Name:        "dev-controller",
			Description: "A default controller created in dev mode",
		},
		DevController: true,
	}

	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig
	exp.Listeners[1].RawConfig = actual.Listeners[1].RawConfig
	exp.Seals[0].Config["key"] = actual.Seals[0].Config["key"]
	exp.Seals[1].Config["key"] = actual.Seals[1].Config["key"]
	exp.Controller.DevControllerKey = actual.Seals[0].Config["key"]
	exp.Controller.DevWorkerAuthKey = actual.Seals[1].Config["key"]

	assert.Equal(t, exp, actual)
}

func TestDevWorker(t *testing.T) {
	actual, err := DevWorker()
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
					TLSDisable:            true,
					Purpose:               []string{"worker-alpn-tls"},
					ProxyProtocolBehavior: "allow_authorized",
					ProxyProtocolAuthorizedAddrs: []*sockaddr.SockAddrMarshaler{
						{SockAddr: addr},
					},
				},
			},
			Telemetry: &configutil.Telemetry{
				DisableHostname:         true,
				PrometheusRetentionTime: 24 * time.Hour,
				UsageGaugePeriod:        10 * time.Minute,
				MaximumGaugeCardinality: 500,
			},
		},
		Worker: &Worker{
			Name:        "dev-worker",
			Description: "A default worker created in dev mode",
			Controllers: []string{"127.0.0.1"},
		},
	}

	exp.Listeners[0].RawConfig = actual.Listeners[0].RawConfig

	assert.Equal(t, exp, actual)
}

func TestConfigDecrypt(t *testing.T) {
	const (
		clr = `
kms "aead" {
  purpose = "config"
  aead_type = "aes-gcm"
  key = "c964AJj8VW8w4hKz/Jd8MvuLt0kkcjVuFqMiMvTvvN8="
}

kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key ="eb78KqCwowELYnkOOko/XYz01q1ax3g76J1vCAvt5dQ="
}`

		enc = `
kms "aead" {
  purpose = "config"
  aead_type = "aes-gcm"
  key = "c964AJj8VW8w4hKz/Jd8MvuLt0kkcjVuFqMiMvTvvN8="
}

kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key ="{{decrypt(Ckh57d4NA6nsnRKV6DiHTyfwLIakdhN8w7qdPJgo-KWnBdlEKv3NQkUFbouU0eorSGik1Qbca5xEy2NqYT9UYj_GUGo6hHz13MEqAA)}}"
}`
	)

	kmses, err := configutil.ParseKMSes(enc)
	assert.NoError(t, err)

	var kms = &configutil.KMS{}
	for _, k := range kmses {
		for _, p := range k.Purpose {
			if p == "config" {
				kms = k
			}
		}
	}

	got, err := configDecrypt(enc, kms)
	assert.NoError(t, err)

	assert.Equal(t, strings.TrimSpace(got), strings.TrimSpace(clr))
}
