// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var registerTestProtocol *sync.Once = new(sync.Once)

// TestRegisterSummaryAllocFunc registers "TEST" as a protocol for all container types
// The channel summary will include the following:
//
//	BaseChannelSummary{Id: "TEST_CHANNEL_ID", ConnectionRecordingId: "TEST_CONNECTION_RECORDING_ID"}
//
// The connection summary will include the following:
//
//	BaseConnectionSummary{Id: "TEST_CONNECTION_ID", ChannelCount: 1}
//
// The session summary will include the following:
//
//	BaseSessionSummary{Id: "TEST_SESSION_ID", ConnectionCount: 1}
func TestRegisterSummaryAllocFunc(t *testing.T) Protocol {
	protocol := Protocol("TEST")
	registerTestProtocol.Do(func() {
		require.NoError(t,
			RegisterSummaryAllocFunc(protocol, ChannelContainer, func(ctx context.Context) Summary {
				return &BaseChannelSummary{Id: "TEST_CHANNEL_ID", ConnectionRecordingId: "TEST_CONNECTION_RECORDING_ID"}
			}))

		require.NoError(t,
			RegisterSummaryAllocFunc(protocol, SessionContainer, func(ctx context.Context) Summary {
				return &BaseSessionSummary{Id: "TEST_SESSION_ID", ConnectionCount: 1}
			}))

		require.NoError(t,
			RegisterSummaryAllocFunc(protocol, ConnectionContainer, func(ctx context.Context) Summary {
				return &BaseConnectionSummary{Id: "TEST_CONNECTION_ID", ChannelCount: 1}
			}))
	})
	return protocol
}

func TestSessionRecordingMeta(s string, p Protocol) *SessionRecordingMeta {
	return &SessionRecordingMeta{
		Id:       s,
		Protocol: p,
	}
}

func TestSessionMeta(s string) *SessionMeta {
	return &SessionMeta{
		PublicId: s,
		Endpoint: "myhost:12345",
		User: &User{
			PublicId: "user123",
			Scope: Scope{
				PublicId: "global",
				Type:     "global",
			},
		},
		StaticHost: &StaticHost{
			PublicId: "host123",
			Catalog: StaticHostCatalog{
				PublicId:  "staticcat123",
				ProjectId: "proj123",
			},
			Address: "127.0.0.1",
		},
		Target: &Target{
			PublicId: "target123",
			Scope: Scope{
				PublicId: "proj123",
				Type:     "project",
				ParentId: "org123",
			},
			DefaultPort:            0,
			SessionMaxSeconds:      0,
			SessionConnectionLimit: 0,
		},
		Worker: &Worker{
			PublicId: "w_12345",
			Version:  "0.25.5",
			Sha:      "beepboopgitsha",
		},
		StaticJSONCredentials: []StaticJsonCredential{
			{
				PublicId:   "scjson123",
				ObjectHmac: []byte("hmac"),
				CredentialStore: StaticCredentialStore{
					PublicId:  "scs123",
					ProjectId: "proj123",
				},
			},
		},
		VaultGenericLibraries: []VaultGenericLibrary{
			{
				PublicId:       "vl123",
				VaultPath:      "/a/path",
				HttpMethod:     "GET",
				CredentialType: "magic",
				CredentialStore: VaultCredentialStore{
					PublicId:      "vcs123",
					ProjectId:     "proj123",
					VaultAddress:  "an/address",
					Namespace:     "name",
					TlsServerName: "imaserver",
					TlsSkipVerify: false,
				},
			},
		},
	}
}
