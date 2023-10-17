// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scope

import (
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/stretchr/testify/assert"
)

func Test_Map(t *testing.T) {
	tests := []struct {
		name       string
		s          string
		want       Type
		wantPrefix string
	}{
		{
			name:       "global",
			s:          "global",
			want:       Global,
			wantPrefix: globals.GlobalPrefix,
		},
		{
			name:       "org",
			s:          "org",
			want:       Org,
			wantPrefix: globals.OrgPrefix,
		},
		{
			name:       "proj",
			s:          "project",
			want:       Project,
			wantPrefix: globals.ProjectPrefix,
		},
		{
			name:       "unknown",
			s:          "blahblah",
			want:       Unknown,
			wantPrefix: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := Map[tt.s]
			assert.Equal(tt.want, got)
			assert.Equalf(tt.wantPrefix, got.Prefix(), "unexpected prefix for %s", tt.s)
		})
	}
}
