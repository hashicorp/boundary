package static

import (
	"context"
	"errors"
	"strings"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/host/static/store"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/stretchr/testify/assert"
)

func TestRepository_New(t *testing.T) {

	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	type args struct {
		r       db.Reader
		w       db.Writer
		wrapper wrapping.Wrapper
	}

	var tests = []struct {
		name      string
		args      args
		want      *Repository
		wantIsErr error
	}{
		{
			name: "valid",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: wrapper,
			},
			want: &Repository{
				reader:  rw,
				writer:  rw,
				wrapper: wrapper,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r:       nil,
				w:       rw,
				wrapper: wrapper,
			},
			want:      nil,
			wantIsErr: ErrNilParameter,
		},
		{
			name: "nil-writer",
			args: args{
				r:       rw,
				w:       nil,
				wrapper: wrapper,
			},
			want:      nil,
			wantIsErr: ErrNilParameter,
		},
		{
			name: "nil-wrapper",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: nil,
			},
			want:      nil,
			wantIsErr: ErrNilParameter,
		},
		{
			name: "all-nils",
			args: args{
				r:       nil,
				w:       nil,
				wrapper: nil,
			},
			want:      nil,
			wantIsErr: ErrNilParameter,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.wrapper)
			if tt.wantIsErr != nil {
				assert.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %v", tt.wantIsErr)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				if assert.NotNil(got) {
					assert.Equal(tt.want, got)
				}
			}
		})
	}
}

func TestRepository_CreateCatalog(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer cleanup()
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(t, err)
	assert.NotNil(t, repo)

	_, prj := iam.TestScopes(t, conn)

	var tests = []struct {
		name      string
		in        *HostCatalog
		opts      []Option
		want      *HostCatalog
		wantIsErr error
	}{
		{
			name:      "nil-catalog",
			in:        nil,
			want:      nil,
			wantIsErr: ErrNilParameter,
		},
		{
			name: "valid-no-options",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId: prj.GetPublicId(),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId: prj.GetPublicId(),
				},
			},
		},
		{
			name: "valid-with-name",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId: prj.GetPublicId(),
					Name:    "test-name-repo",
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId: prj.GetPublicId(),
					Name:    "test-name-repo",
				},
			},
		},
		{
			name: "valid-with-description",

			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:     prj.GetPublicId(),
					Description: ("test-description-repo"),
				},
			},
			want: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId:     prj.GetPublicId(),
					Description: ("test-description-repo"),
				},
			},
		},
		{
			name: "invalid-duplicate-name",
			in: &HostCatalog{
				HostCatalog: &store.HostCatalog{
					ScopeId: prj.GetPublicId(),
					Name:    "test-name-repo",
				},
			},
			wantIsErr: ErrNotUnique,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := repo.CreateCatalog(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != nil {
				assert.Error(err)
				assert.Truef(errors.Is(err, tt.wantIsErr), "want err: %v got: %v", tt.wantIsErr, err)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				if assert.NotNil(got) {
					assertPublicID(t, "sthc", got.PublicId)

					assert.Equal(tt.want.Name, got.Name)
					assert.Equal(tt.want.Description, got.Description)
					assert.Equal(got.CreateTime, got.UpdateTime)

				}
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
