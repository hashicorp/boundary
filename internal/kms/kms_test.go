package kms

import (
	"context"
	"testing"
	"time"

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
				writer: rw,
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

func TestMonitorTableRewrappingRuns(t *testing.T) {
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
	sqldb, err := conn.SqlDB(testCtx)
	require.NoError(t, err)

	t.Run("does-nothing-when-no-run-available", func(t *testing.T) {
		callbackCalled := false
		tableNameToRewrapFn["auth_token"] = func(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kms *Kms) error {
			callbackCalled = true
			return nil
		}
		err = kmsCache.MonitorTableRewrappingRuns(testCtx, "auth_token")
		require.NoError(t, err)
		assert.False(t, callbackCalled, "auth_token callback should not have been called")
	})
	t.Run("returns-an-error-when-no-rewrapping-function-registered", func(t *testing.T) {
		tableNameToRewrapFn = make(map[string]RewrapFn)
		err = kmsCache.MonitorTableRewrappingRuns(testCtx, "auth_token")
		require.Error(t, err)
	})
	t.Run("does-nothing-when-another-run-is-running", func(t *testing.T) {
		var kvToDestroy wrappingKms.KeyVersion
		for _, key := range keys {
			if key.Purpose == wrappingKms.KeyPurpose(KeyPurposeDatabase.String()) {
				kvToDestroy = key.Versions[0]
			}
		}
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job(key_id) values ($1)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_token', 100)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_oidc_method', 100)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "update kms_data_key_version_destruction_job_run set is_running=true where key_id=$1 and table_name='auth_oidc_method'", kvToDestroy.Id)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(testCtx, "truncate kms_data_key_version_destruction_job, kms_data_key_version_destruction_job_run CASCADE")
			require.NoError(t, err)
		})
		callbackCalled := false
		tableNameToRewrapFn["auth_token"] = func(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kms *Kms) error {
			callbackCalled = true
			return nil
		}
		err = kmsCache.MonitorTableRewrappingRuns(testCtx, "auth_token")
		require.NoError(t, err)
		assert.False(t, callbackCalled, "auth_token callback should not have been called")
	})
	t.Run("chooses-one-when-one-run-available", func(t *testing.T) {
		var kvToDestroy wrappingKms.KeyVersion
		for _, key := range keys {
			if key.Purpose == wrappingKms.KeyPurpose(KeyPurposeDatabase.String()) {
				kvToDestroy = key.Versions[0]
			}
		}
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job(key_id) values ($1)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_token', 100)", kvToDestroy.Id)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(testCtx, "truncate kms_data_key_version_destruction_job, kms_data_key_version_destruction_job_run CASCADE")
			require.NoError(t, err)
		})
		callbackCalled := make(chan struct{})
		returnFromCallback := make(chan struct{})
		tableNameToRewrapFn["auth_token"] = func(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kms *Kms) error {
			close(callbackCalled)
			assert.Equal(t, "global", scopeId)
			// Block here until we want it to return
			<-returnFromCallback
			return nil
		}
		monitorErrCh := make(chan error)
		// Run in goroutine so we can check status while the job is running
		go func() {
			monitorErrCh <- kmsCache.MonitorTableRewrappingRuns(testCtx, "auth_token")
		}()
		// Wait for callback to have been called
		select {
		case <-callbackCalled:
		case err := <-monitorErrCh:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("Callback had not been called after 5 seconds")
			return
		}
		// Now we know that the job is waiting for the callback to return, lets
		// do some db inspection
		row := sqldb.QueryRowContext(testCtx, "select is_running from kms_data_key_version_destruction_job_run where key_id=$1 and table_name='auth_token'", kvToDestroy.Id)
		isRunning := false
		err = row.Scan(&isRunning)
		require.NoError(t, err)
		assert.True(t, isRunning, "is_running should be set to true")
		// Trigger callback to return
		close(returnFromCallback)
		// Wait for function to return
		select {
		case err := <-monitorErrCh:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("Function has not returned 5 seconds after callback finished")
			return
		}
		// Lets look at the db state again after the function has returned
		row = sqldb.QueryRowContext(testCtx, "select completed_count, is_running from kms_data_key_version_destruction_job_run where key_id=$1 and table_name='auth_token'", kvToDestroy.Id)
		completedCount := 0
		isRunning = false
		err = row.Scan(&completedCount, &isRunning)
		require.NoError(t, err)
		assert.EqualValues(t, completedCount, 100, "completed_count should have been updated")
		assert.False(t, isRunning, "is_running should be set to false")
	})
	t.Run("chooses-oldest-when-two-runs-available", func(t *testing.T) {
		var kvsToDestroy []wrappingKms.KeyVersion
		for _, key := range keys {
			switch key.Purpose {
			case wrappingKms.KeyPurpose(KeyPurposeDatabase.String()), wrappingKms.KeyPurpose(KeyPurposeTokens.String()):
				kvsToDestroy = append(kvsToDestroy, key.Versions[0])
			}
		}
		require.Len(t, kvsToDestroy, 2)
		for _, kvToDestroy := range kvsToDestroy {
			_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job(key_id) values ($1)", kvToDestroy.Id)
			require.NoError(t, err)
			_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_token', 100)", kvToDestroy.Id)
			require.NoError(t, err)
		}
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(testCtx, "truncate kms_data_key_version_destruction_job, kms_data_key_version_destruction_job_run CASCADE")
			require.NoError(t, err)
		})
		rewrappedKeyVersion := ""
		tableNameToRewrapFn["auth_token"] = func(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kms *Kms) error {
			rewrappedKeyVersion = dataKeyVersionId
			return nil
		}
		err = kmsCache.MonitorTableRewrappingRuns(testCtx, "auth_token")
		require.NoError(t, err)
		assert.Equal(t, rewrappedKeyVersion, kvsToDestroy[0].Id, "auth_token callback should have been called with the oldest job")
	})
	t.Run("resumes-running-one-when-two-runs-available-even-if-not-oldest", func(t *testing.T) {
		var kvsToDestroy []wrappingKms.KeyVersion
		for _, key := range keys {
			switch key.Purpose {
			case wrappingKms.KeyPurpose(KeyPurposeDatabase.String()), wrappingKms.KeyPurpose(KeyPurposeTokens.String()):
				kvsToDestroy = append(kvsToDestroy, key.Versions[0])
			}
		}
		require.Len(t, kvsToDestroy, 2)
		for i, kvToDestroy := range kvsToDestroy {
			_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job(key_id) values ($1)", kvToDestroy.Id)
			require.NoError(t, err)
			_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_token', 100)", kvToDestroy.Id)
			require.NoError(t, err)
			if i == 1 {
				_, err = sqldb.ExecContext(testCtx, "update kms_data_key_version_destruction_job_run set is_running=true where key_id=$1 and table_name='auth_token'", kvToDestroy.Id)
				require.NoError(t, err)
			}
		}
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(testCtx, "truncate kms_data_key_version_destruction_job, kms_data_key_version_destruction_job_run CASCADE")
			require.NoError(t, err)
		})
		rewrappedKeyVersion := ""
		tableNameToRewrapFn["auth_token"] = func(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kms *Kms) error {
			rewrappedKeyVersion = dataKeyVersionId
			return nil
		}
		err = kmsCache.MonitorTableRewrappingRuns(testCtx, "auth_token")
		require.NoError(t, err)
		assert.Equal(t, rewrappedKeyVersion, kvsToDestroy[1].Id, "auth_token callback should have been called with the already running job")
	})
	t.Run("updates-the-running-state-even-when-context-canceled", func(t *testing.T) {
		var kvToDestroy wrappingKms.KeyVersion
		for _, key := range keys {
			if key.Purpose == wrappingKms.KeyPurpose(KeyPurposeDatabase.String()) {
				kvToDestroy = key.Versions[0]
			}
		}
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job(key_id) values ($1)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_token', 100)", kvToDestroy.Id)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(testCtx, "truncate kms_data_key_version_destruction_job, kms_data_key_version_destruction_job_run CASCADE")
			require.NoError(t, err)
		})
		callbackCalled := make(chan struct{})
		tableNameToRewrapFn["auth_token"] = func(ctx context.Context, dataKeyVersionId string, scopeId string, reader db.Reader, writer db.Writer, kms *Kms) error {
			close(callbackCalled)
			// Block here until we want it to return
			<-ctx.Done()
			return ctx.Err()
		}
		monitorErrCh := make(chan error)
		newCtx, cancel := context.WithCancel(testCtx)
		defer cancel()
		// Run in goroutine so we can check status while the job is running
		go func() {
			monitorErrCh <- kmsCache.MonitorTableRewrappingRuns(newCtx, "auth_token")
		}()
		// Wait for callback to have been called
		select {
		case <-callbackCalled:
		case err := <-monitorErrCh:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("Callback had not been called after 5 seconds")
			return
		}
		// Now we know that the job is waiting for the callback to return, lets
		// do some db inspection
		row := sqldb.QueryRowContext(testCtx, "select is_running from kms_data_key_version_destruction_job_run where key_id=$1 and table_name='auth_token'", kvToDestroy.Id)
		isRunning := false
		err = row.Scan(&isRunning)
		require.NoError(t, err)
		assert.True(t, isRunning, "is_running should be set to true")
		// Trigger callback to return
		cancel()
		// Wait for function to return
		select {
		case err := <-monitorErrCh:
			require.Equal(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Fatalf("Function has not returned 5 seconds after callback finished")
			return
		}
		// Lets look at the db state again after the function has returned
		row = sqldb.QueryRowContext(testCtx, "select completed_count, is_running from kms_data_key_version_destruction_job_run where key_id=$1 and table_name='auth_token'", kvToDestroy.Id)
		completedCount := 0
		isRunning = false
		err = row.Scan(&completedCount, &isRunning)
		require.NoError(t, err)
		assert.EqualValues(t, completedCount, 100, "completed_count should have been updated")
		assert.False(t, isRunning, "is_running should be set to false")
	})
}

func TestMonitorDataKeyVersionDestruction(t *testing.T) {
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
	sqldb, err := conn.SqlDB(testCtx)
	require.NoError(t, err)

	t.Run("does-nothing-when-no-jobs-available", func(t *testing.T) {
		err = kmsCache.MonitorDataKeyVersionDestruction(testCtx)
		require.NoError(t, err)
	})
	t.Run("does-nothing-when-the-job-isnt-completed", func(t *testing.T) {
		var kvToDestroy wrappingKms.KeyVersion
		for _, key := range keys {
			if key.Purpose == wrappingKms.KeyPurpose(KeyPurposeDatabase.String()) {
				kvToDestroy = key.Versions[0]
			}
		}
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job(key_id) values ($1)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_token', 100)", kvToDestroy.Id)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(testCtx, "truncate kms_data_key_version_destruction_job, kms_data_key_version_destruction_job_run CASCADE")
			require.NoError(t, err)
		})
		err = kmsCache.MonitorDataKeyVersionDestruction(testCtx)
		require.NoError(t, err)
		row := sqldb.QueryRowContext(testCtx, "select exists(select 1 from kms_data_key_version_destruction_job where key_id=$1)", kvToDestroy.Id)
		exists := false
		err = row.Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "the job should still exist")
	})
	t.Run("deletes-the-key-when-the-job-is-completed", func(t *testing.T) {
		var kvToDestroy wrappingKms.KeyVersion
		for _, key := range keys {
			if key.Purpose == wrappingKms.KeyPurpose(KeyPurposeDatabase.String()) {
				kvToDestroy = key.Versions[0]
			}
		}
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job(key_id) values ($1)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "insert into kms_data_key_version_destruction_job_run(key_id, table_name, total_count) values ($1, 'auth_token', 100)", kvToDestroy.Id)
		require.NoError(t, err)
		_, err = sqldb.ExecContext(testCtx, "update kms_data_key_version_destruction_job_run set completed_count=100 where key_id=$1 and table_name='auth_token'", kvToDestroy.Id)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err = sqldb.ExecContext(testCtx, "truncate kms_data_key_version_destruction_job, kms_data_key_version_destruction_job_run CASCADE")
			require.NoError(t, err)
		})
		err = kmsCache.MonitorDataKeyVersionDestruction(testCtx)
		require.NoError(t, err)
		row := sqldb.QueryRowContext(testCtx, "select exists(select 1 from kms_data_key_version_destruction_job where key_id=$1)", kvToDestroy.Id)
		exists := false
		err = row.Scan(&exists)
		require.NoError(t, err)
		// The job is deleted by virtue of cascading foreign key references
		assert.False(t, exists, "the job should be deleted")
	})
}

type invalidReader struct {
	db.Reader
}

type invalidWriter struct {
	db.Writer
}
