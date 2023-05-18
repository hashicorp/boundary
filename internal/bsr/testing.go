// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

func TestSessionMeta(s string, p Protocol) *SessionMeta {
	scope := Scope{
		PublicId: "global",
		Type:     "global",
	}
	staticCatalog := StaticHostCatalog{
		PublicId:  "staticcat123",
		ProjectId: "proj123",
	}
	creds := make([]StaticCredential, 0)
	c := StaticJsonCredential{
		PublicId:   "scjson123",
		ProjectId:  "proj123",
		ObjectHmac: []byte("hmac"),
	}
	creds = append(creds, c)
	staticCredentialStore := make([]StaticCredentialStore, 0)
	scs := StaticCredentialStore{
		PublicId:    "scs123",
		ProjectId:   "proj123",
		Credentials: creds,
	}
	staticCredentialStore = append(staticCredentialStore, scs)
	vcreds := make([]DynamicCredentialLibraries, 0)
	v := VaultLibrary{
		PublicId:       "vl123",
		ProjectId:      "proj123",
		VaultPath:      "/a/path",
		HttpMethod:     "GET",
		CredentialType: "magic",
	}
	vcreds = append(vcreds, v)
	vaultCredentialStore := make([]VaultCredentialStore, 0)
	vcs := VaultCredentialStore{
		PublicId:            "vcs123",
		ProjectId:           "proj123",
		VaultAddress:        "an/address",
		Namespace:           "name",
		TlsServerName:       "imaserver",
		TlsSkipVerify:       false,
		CredentialLibraries: vcreds,
	}
	vaultCredentialStore = append(vaultCredentialStore, vcs)
	sessionMeta := &SessionMeta{
		Id:       s,
		Protocol: p,
		User: &User{
			PublicId: "user123",
			Scope:    scope,
		},
		StaticHost: &StaticHost{
			PublicId: "host123",
			Catalog:  staticCatalog,
			Address:  "127.0.0.1",
		},
		Target: &Target{
			PublicId:               "target123",
			ProjectId:              "proj123",
			Scope:                  scope,
			DefaultPort:            0,
			SessionMaxSeconds:      0,
			SessionConnectionLimit: 0,
		},
		Worker: &Worker{
			PublicId: "w_12345",
			Version:  "0.25.5",
			Sha:      "beepboopgitsha",
		},
		StaticCredentialStore: staticCredentialStore,
		VaultCredentialStore:  vaultCredentialStore,
	}
	return sessionMeta
}
