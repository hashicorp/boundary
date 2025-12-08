// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/stretchr/testify/assert"
)

func TestAppToken_IsActive(t *testing.T) {
	now := timestamp.Now()
	past := timestamp.New(now.AsTime().Add(-1 * time.Hour))
	future := timestamp.New(now.AsTime().Add(1 * time.Hour))

	tests := []struct {
		name  string
		token *AppToken
		want  bool
	}{
		{
			name: "active token",
			token: &AppToken{
				Revoked:                   false,
				ExpirationTime:            future,
				ApproximateLastAccessTime: now,
				TimeToStaleSeconds:        3600,
			},
			want: true,
		},
		{
			name: "revoked token",
			token: &AppToken{
				Revoked:                   true,
				ExpirationTime:            future,
				ApproximateLastAccessTime: now,
				TimeToStaleSeconds:        3600,
			},
			want: false,
		},
		{
			name: "expired token",
			token: &AppToken{
				Revoked:                   false,
				ExpirationTime:            past,
				ApproximateLastAccessTime: now,
				TimeToStaleSeconds:        3600,
			},
			want: false,
		},
		{
			name: "stale token",
			token: &AppToken{
				Revoked:                   false,
				ExpirationTime:            future,
				ApproximateLastAccessTime: past,
				TimeToStaleSeconds:        1800,
			},
			want: false,
		},
		{
			name: "no TimeToStaleSeconds set",
			token: &AppToken{
				Revoked:                   false,
				ExpirationTime:            future,
				ApproximateLastAccessTime: past,
				TimeToStaleSeconds:        0,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.token.IsActive())
		})
	}
}
