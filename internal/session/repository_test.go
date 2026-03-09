// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	testReader := strings.NewReader("notrandom")

	type args struct {
		r    db.Reader
		w    db.Writer
		k    *kms.Kms
		opts []Option
	}
	tests := []struct {
		name          string
		args          args
		want          *Repository
		wantErr       bool
		wantErrString string
	}{
		{
			name: "valid",
			args: args{
				r: rw,
				w: rw,
				k: testKms,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				defaultLimit: db.DefaultLimit,
				permissions:  nil,
				randomReader: rand.Reader,
			},
			wantErr: false,
		},
		{
			name: "nil-writer",
			args: args{
				r: rw,
				w: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "session.NewRepository: nil writer: parameter violation: error #100",
		},
		{
			name: "nil-reader",
			args: args{
				r: nil,
				w: rw,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "session.NewRepository: nil reader: parameter violation: error #100",
		},
		{
			name: "providing-options",
			args: args{
				r: rw,
				w: rw,
				k: testKms,
				opts: []Option{
					WithLimit(100),
					WithPermissions(&perms.UserPermissions{}),
					WithRandomReader(testReader),
				},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				defaultLimit: 100,
				permissions:  &perms.UserPermissions{},
				randomReader: testReader,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(ctx, tt.args.r, tt.args.w, tt.args.k, tt.args.opts...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrString, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_convertToSessions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	composedOf := TestSessionParams(t, conn, rootWrapper, iamRepo)
	sess, err := New(ctx, composedOf)
	require.NoError(t, err)
	sessionWrapper, err := kmsCache.GetWrapper(ctx, sess.ProjectId, kms.KeyPurposeSessions)
	require.NoError(t, err)
	sess, err = repo.CreateSession(ctx, sessionWrapper, sess, []string{"0.0.0.0"})
	require.NoError(t, err)

	query := fmt.Sprintf(listSessionsTemplate, "termination_reason is null", 1000)
	rows, err := rw.Query(ctx, query, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := rows.Close()
		require.NoError(t, err)
	})

	var sessionsList []*sessionListView
	for rows.Next() {
		var s sessionListView
		err := rw.ScanRows(ctx, rows, &s)
		require.NoError(t, err)
		sessionsList = append(sessionsList, &s)
	}
	require.NoError(t, rows.Err())

	sessions, err := repo.convertToSessions(ctx, sessionsList)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	// Check that encrypted values are redacted
	sess.CtCertificatePrivateKey = nil
	sess.CertificatePrivateKey = nil
	sess.CtTofuToken = nil
	sess.TofuToken = nil
	sess.KeyId = ""
	// CorrelationId is an internal attribute and not returned
	sess.CorrelationId = ""
	assert.Equal(t, sessions[0], sess)
}
