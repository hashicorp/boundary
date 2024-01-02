// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package bsr

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
