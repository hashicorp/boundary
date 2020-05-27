package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/kms/store"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestNewKeyEntry(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	org := testOrg(t, conn)

	id := testId(t)

	type args struct {
		organizationPublicId string
		keyId                string
		key                  []byte
		opt                  []Option
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantErrMsg string
		want       *KeyEntry
	}{
		{
			name: "valid",
			args: args{
				key:                  []byte("valid-" + id),
				keyId:                "valid-" + id,
				organizationPublicId: org.PublicId,
				opt:                  []Option{WithParentKeyId("valid-" + id)},
			},
			wantErr: false,
			want: &KeyEntry{
				KeyEntry: &store.KeyEntry{
					Key:         []byte("valid-" + id),
					KeyId:       "valid-" + id,
					ScopeId:     org.PublicId,
					ParentKeyId: "valid-" + id,
				},
			},
		},
		{
			name: "valid-no-parent",
			args: args{
				key:                  []byte("valid-no-parent-" + id),
				keyId:                "valid-no-parent-" + id,
				organizationPublicId: org.PublicId,
			},
			wantErr: false,
			want: &KeyEntry{
				KeyEntry: &store.KeyEntry{
					Key:     []byte("valid-no-parent-" + id),
					KeyId:   "valid-no-parent-" + id,
					ScopeId: org.PublicId,
				},
			},
		},
		{
			name: "nil-key",
			args: args{
				key:                  nil,
				keyId:                "nil-key-" + id,
				organizationPublicId: org.PublicId,
				opt:                  []Option{WithParentKeyId("nil-key-" + id)},
			},
			wantErr:    true,
			wantErrMsg: "new key entry: missing key nil parameter",
			want:       nil,
		},
		{
			name: "no-key-id",
			args: args{
				key:                  []byte("no-key-id-" + id),
				keyId:                "",
				organizationPublicId: org.PublicId,
				opt:                  []Option{WithParentKeyId("no-key-id-" + id)},
			},
			wantErr:    true,
			wantErrMsg: "new key entry: missing key id nil parameter",
			want:       nil,
		},
		{
			name: "no-org-id",
			args: args{
				key:                  []byte("no-org-id-" + id),
				keyId:                "no-org-id-" + id,
				organizationPublicId: "",
				opt:                  []Option{WithParentKeyId("no-org-id-" + id)},
			},
			wantErr:    true,
			wantErrMsg: "new key entry: missing organization id nil parameter",
			want:       nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKeyEntry(tt.args.organizationPublicId, tt.args.keyId, tt.args.key, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want.KeyEntry, got.KeyEntry)
		})
	}
}

func testOrg(t *testing.T, conn *gorm.DB) (org *iam.Scope) {
	t.Helper()
	assert := assert.New(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := iam.NewRepository(rw, rw, wrapper)
	assert.NoError(err)

	o, err := iam.NewOrganization()
	assert.NoError(err)
	o, err = repo.CreateScope(context.Background(), o)
	assert.NoError(err)
	assert.NotNil(o)
	assert.NotEmpty(o.GetPublicId())
	return o
}
func testId(t *testing.T) string {
	id, err := uuid.GenerateUUID()
	assert.NoError(t, err)
	return id
}
