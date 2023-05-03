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
	}
	return sessionMeta
}
