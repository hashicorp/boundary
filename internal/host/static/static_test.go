package static

import (
	"strings"
	"testing"

	"github.com/hashicorp/watchtower/internal/host/static/store"
	"github.com/stretchr/testify/assert"
)

func TestHostCatalog_New(t *testing.T) {

	type args struct {
		scopeId string
		opts    []Option
	}

	var tests = []struct {
		name    string
		args    args
		want    *HostCatalog
		wantErr bool
	}{
		{
			name: "blank-scopeId",
			args: args{
				scopeId: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				scopeId: "1234567890",
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId: "1234567890",
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				scopeId: "1234567890",
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId: "1234567890",
					Name:    "test-name",
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				scopeId: "1234567890",
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:     "1234567890",
					Description: "test-description",
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewHostCatalog(tt.args.scopeId, tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				assert.NotNil(got)
				assertPublicID(t, "sthc", got.PublicId)
				tt.want.PublicId = got.PublicId
				assert.Equal(tt.want, got)
			}
		})
	}
}

func assertPublicID(t *testing.T, prefix, actual string) {
	t.Helper()
	if actual == "" {
		t.Errorf("PublicId is empty")
	}
	parts := strings.Split(actual, "_")
	switch {
	case len(parts) > 2:
		t.Errorf("want one '_' in PublicID, got multiple in %q", actual)
	case len(parts) < 2:
		t.Errorf("want one '_' in PublicID, got none in %q", actual)
	}

	if prefix != parts[0] {
		t.Errorf("PublicID want prefix: %q, got: %q in %q", prefix, parts[0], actual)
	}
}
