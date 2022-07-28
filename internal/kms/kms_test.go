package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	wrappingKms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_New(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	tests := []struct {
		name            string
		r               *db.Db
		w               *db.Db
		want            *Kms
		wantErr         bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "nil-reader",
			w:               rw,
			wantErr:         true,
			wantErrContains: "missing reader",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "nil-writer",
			r:               rw,
			wantErr:         true,
			wantErrContains: "missing writer",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name: "success",
			r:    rw,
			w:    rw,
			want: &Kms{
				reader: rw,
				underlying: func() *wrappingKms.Kms {
					purposes := make([]wrappingKms.KeyPurpose, 0, len(ValidDekPurposes()))
					for _, p := range ValidDekPurposes() {
						purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
					}
					purposes = append(purposes, wrappingKms.KeyPurpose(KeyPurposeWorkerAuth.String()),
						wrappingKms.KeyPurpose(KeyPurposeWorkerAuthStorage.String()), wrappingKms.KeyPurpose(KeyPurposeRecovery.String()))

					wrapped, err := wrappingKms.New(db.NewChangeSafeDbwReader(rw), db.NewChangeSafeDbwWriter(rw), purposes)
					require.NoError(t, err)
					return wrapped
				}(),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := New(testCtx, tc.r, tc.w)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrMatch != nil {
					assert.Truef(errors.Match(tc.wantErrMatch, err), "expected %q and got err: %+v", tc.wantErrMatch.Code, err)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func Test_NewUsingReaderWriter(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	tests := []struct {
		name            string
		r               db.Reader
		w               db.Writer
		want            *Kms
		wantErr         bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "nil-reader",
			w:               rw,
			wantErr:         true,
			wantErrContains: "missing reader",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "nil-writer",
			r:               rw,
			wantErr:         true,
			wantErrContains: "missing writer",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "invalid-reader",
			r:               &invalidReader{},
			w:               rw,
			wantErr:         true,
			wantErrContains: "unable to convert reader to db.Db",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "invalid-writer",
			r:               rw,
			w:               &invalidWriter{},
			wantErr:         true,
			wantErrContains: "unable to convert writer to db.Db",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name: "success",
			r:    rw,
			w:    rw,
			want: &Kms{
				reader: rw,
				underlying: func() *wrappingKms.Kms {
					purposes := stdNewKmsPurposes()
					wrapped, err := wrappingKms.New(db.NewChangeSafeDbwReader(rw), db.NewChangeSafeDbwWriter(rw), purposes)
					require.NoError(t, err)
					return wrapped
				}(),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := NewUsingReaderWriter(testCtx, tc.r, tc.w)
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrMatch != nil {
					assert.Truef(errors.Match(tc.wantErrMatch, err), "expected %q and got err: %+v", tc.wantErrMatch.Code, err)
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.Equal(tc.want, got)
		})
	}
}

func Test_ListKeys(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	extWrapper := db.TestWrapper(t)
	kmsCache := TestKms(t, conn, extWrapper)
	err := kmsCache.CreateKeys(testCtx, "global")
	require.NoError(t, err)
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		keys, err := kmsCache.ListKeys(testCtx, "global")
		require.NoError(t, err)
		require.Len(t, keys, 7)
	})
	t.Run("unknown-scope", func(t *testing.T) {
		t.Parallel()
		_, err := kmsCache.ListKeys(testCtx, "myscope")
		assert.True(t, errors.IsNotFoundError(err))
	})
}

type invalidReader struct {
	db.Reader
}

type invalidWriter struct {
	db.Writer
}
