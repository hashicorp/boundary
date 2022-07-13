package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-dbw"
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

					r := dbw.New(rw.UnderlyingDB())
					w := dbw.New(rw.UnderlyingDB())
					wrapped, err := wrappingKms.New(r, w, purposes)
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
			wantErrContains: "unable to convert to db.DB",
			wantErrMatch:    errors.T(errors.InvalidParameter),
		},
		{
			name:            "invalid-writer",
			r:               rw,
			w:               &invalidWriter{},
			wantErr:         true,
			wantErrContains: "unable to convert to db.DB",
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
					r := dbw.New(rw.UnderlyingDB())
					w := dbw.New(rw.UnderlyingDB())
					wrapped, err := wrappingKms.New(r, w, purposes)
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

type invalidReader struct {
	db.Reader
}

type invalidWriter struct {
	db.Writer
}
