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

func Test_RotateKeys(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	extWrapper := db.TestWrapper(t)
	kmsCache := TestKms(t, conn, extWrapper)
	err := kmsCache.CreateKeys(testCtx, "global")
	require.NoError(t, err)
	rw := db.New(conn)

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		// arrange
		// we're not trying to test the ListKeys function, although we need to use it to validate the rotation
		keys, err := kmsCache.ListKeys(testCtx, "global")
		require.NoError(t, err)
		require.Len(t, keys, 7)

		// act
		err = kmsCache.RotateKeys(testCtx, "global")
		require.NoError(t, err)

		// assert
		keys, err = kmsCache.ListKeys(testCtx, "global")
		require.NoError(t, err)

		keyCount := 0
		for _, key := range keys {
			keyCount += len(key.Versions)
		}

		require.Equal(t, keyCount, 14)
	})

	t.Run("reader provided, missing writer", func(t *testing.T) {
		t.Parallel()
		// arrange
		WithReader := func(reader db.Reader) Option {
			return func(o *options) {
				o.withReader = reader
			}
		}

		// act
		err := kmsCache.RotateKeys(testCtx, "global", WithReader(rw))

		// assert
		assert.ErrorContains(t, err, "missing writer")
	})

	t.Run("writer provided, missing reader", func(t *testing.T) {
		t.Parallel()
		// arrange
		WithWriter := func(writer db.Writer) Option {
			return func(o *options) {
				o.withWriter = writer
			}
		}

		// act
		err := kmsCache.RotateKeys(testCtx, "global", WithWriter(rw))

		// assert
		assert.ErrorContains(t, err, "missing reader")
	})

	t.Run("invalid reader", func(t *testing.T) {
		t.Parallel()
		// act
		err := kmsCache.RotateKeys(testCtx, "global", WithReaderWriter(&invalidReader{}, rw))

		// assert
		assert.ErrorContains(t, err, "unable to convert reader")
	})

	t.Run("invalid writer", func(t *testing.T) {
		t.Parallel()
		// act
		err := kmsCache.RotateKeys(testCtx, "global", WithReaderWriter(rw, &invalidWriter{}))

		// assert
		assert.ErrorContains(t, err, "unable to convert writer")
	})

	// other options are passed directly and shouldn't need to be tested
}

func Test_ListDataKeyVersionDestructionJobs(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	extWrapper := db.TestWrapper(t)
	kmsCache := TestKms(t, conn, extWrapper)
	err := kmsCache.CreateKeys(testCtx, "global")
	require.NoError(t, err)
	err = kmsCache.RotateKeys(testCtx, "global")
	require.NoError(t, err)
	keys, err := kmsCache.ListKeys(testCtx, "global")
	require.NoError(t, err)

	t.Run("lists-no-jobs-when-there-are-none", func(t *testing.T) {
		jobs, err := kmsCache.ListDataKeyVersionDestructionJobs(testCtx, "global")
		require.NoError(t, err)
		assert.Empty(t, jobs)
	})
	t.Run("lists-jobs-when-there-are-some", func(t *testing.T) {
		var kvToDestroy wrappingKms.KeyVersion
		for _, key := range keys {
			if key.Purpose == wrappingKms.KeyPurpose(KeyPurposeDatabase.String()) {
				kvToDestroy = key.Versions[0]
			}
		}
		sqldb, err := conn.SqlDB(testCtx)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job(key_id) values ($1)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_token', 100)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_oidc_method', 200)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "update kms_data_key_version_destruction_job_run set is_running=true where key_id=$1 and table_name='auth_token'", kvToDestroy.Id)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(testCtx, "truncate kms_data_key_version_destruction_job, kms_data_key_version_destruction_job_run CASCADE")
			require.NoError(t, err)
		})
		jobs, err := kmsCache.ListDataKeyVersionDestructionJobs(testCtx, "global")
		require.NoError(t, err)
		require.Len(t, jobs, 1)
		job := jobs[0]
		assert.Equal(t, 0, int(job.CompletedCount))
		assert.Equal(t, 300, int(job.TotalCount))
		assert.Equal(t, "running", job.Status)
		assert.Equal(t, kvToDestroy.Id, job.KeyId)
		assert.Equal(t, "global", job.ScopeId)
	})
	t.Run("lists-no-jobs-when-given-unknown-scope", func(t *testing.T) {
		var kvToDestroy wrappingKms.KeyVersion
		for _, key := range keys {
			if key.Purpose == wrappingKms.KeyPurpose(KeyPurposeDatabase.String()) {
				kvToDestroy = key.Versions[0]
			}
		}
		sqldb, err := conn.SqlDB(testCtx)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job(key_id) values ($1)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_token', 100)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_oidc_method', 200)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "update kms_data_key_version_destruction_job_run set is_running=true where key_id=$1 and table_name='auth_token'", kvToDestroy.Id)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(testCtx, "truncate kms_data_key_version_destruction_job, kms_data_key_version_destruction_job_run CASCADE")
			require.NoError(t, err)
		})
		jobs, err := kmsCache.ListDataKeyVersionDestructionJobs(testCtx, "myscope")
		require.NoError(t, err)
		assert.Empty(t, jobs)
	})
}

type invalidReader struct {
	db.Reader
}

type invalidWriter struct {
	db.Writer
}
