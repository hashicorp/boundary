// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/mitchellh/cli"
	"github.com/stretchr/testify/require"
)

const dbSwapConfig = `
disable_mlock = true

telemetry {
	prometheus_retention_time = "24h"
	disable_hostname = true
}

controller {
	name = "test-controller"
	description = "A default controller created for tests"
	database {
		url = "%s"
	}
}

kms "aead" {
	purpose = "root"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_root"
}

kms "aead" {
	purpose = "worker-auth"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_worker-auth"
}

kms "aead" {
	purpose = "recovery"
	aead_type = "aes-gcm"
	key = "%s"
	key_id = "global_recovery"
}

listener "tcp" {
	purpose = "api"
	address = "127.0.0.1:9600"
	tls_disable = true
}

listener "tcp" {
	address = "127.0.0.1:9601"
	purpose = "cluster"
}
`

const getDatabaseLockQuery = `
select count(*) from pg_locks
-- We need to constrain this query to the correct database because we're not
-- running two distinct Postgres instances, rather two separate databases in
-- the same Postgres instance.
left join pg_database on pg_locks.database = pg_database.oid -- pg_locks.database refers to the database oid, we need to check the name.
where
	pg_locks.locktype       = 'advisory'
	and pg_locks.granted    = true       -- the lock must be granted, not awaited
	and pg_locks.objid      = 3865661975 -- magic number set by the schema manager
	and pg_database.datname = $1
`

func TestReloadControllerDatabase(t *testing.T) {
	td := t.TempDir()

	// Set the close time to something small
	db.CloseSwappedDbDuration = 5 * time.Second

	// Create and migrate database A and B.
	controllerKey := config.DevKeyGeneration()

	closeA, urlA, dbNameA, err := getInitDatabase(t, controllerKey)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeA()) })

	closeB, urlB, dbNameB, err := getInitDatabase(t, controllerKey)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeB()) })

	cmd := testServerCommand(t, testServerCommandOpts{})

	workerAuthKey := config.DevKeyGeneration()
	recoveryKey := config.DevKeyGeneration()
	cfgHcl := fmt.Sprintf(dbSwapConfig, urlA, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	earlyExitChan := make(chan struct{})
	go func() {
		defer wg.Done()
		args := []string{"-config", td + "/config.hcl"}
		exitCode := cmd.Run(args)
		if exitCode != 0 {
			output := cmd.UI.(*cli.MockUi).ErrorWriter.String() + cmd.UI.(*cli.MockUi).OutputWriter.String()
			fmt.Printf("%s: got a non-zero exit status: %s", t.Name(), output)
		}
		// send non-blocking message to a channel to signal that the server has exited
		// this channel is used to avoid waiting for the full timeout in case of early exit
		select {
		case earlyExitChan <- struct{}{}:
		default:
		}
	}()

	// Wait until things are up and running (or timeout).
	select {
	case <-cmd.startedCh:
	case <-earlyExitChan:
		t.Fatal("server exited early")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server to start")
	}

	require.NotNil(t, cmd.schemaManager)

	sqlDB, err := cmd.Server.Database.SqlDB(context.Background())
	require.NoError(t, err)
	require.NotNil(t, sqlDB)

	// Assert we're connected to database A.
	var currentDB string
	row := sqlDB.QueryRow("select current_database();")
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&currentDB))
	require.Equal(t, dbNameA, currentDB)

	// Assert we've grabbed a lock on database A.
	var lock int
	row = sqlDB.QueryRow(getDatabaseLockQuery, dbNameA)
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&lock))
	require.Equal(t, 1, lock)

	// Get old values so we can test against them later.
	oldSchemaManager := cmd.schemaManager
	oldDB := cmd.Server.Database

	// Change config and SIGHUP.
	cfgHcl = fmt.Sprintf(dbSwapConfig, urlB, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for server reload")
	}

	// Assert that the schema manager ptr and value changed
	if oldSchemaManager == cmd.schemaManager {
		t.Fatalf("schema manager pointers are equal (%p). expected difference", oldSchemaManager)
	}
	require.NotEqualValues(t, oldSchemaManager, cmd.schemaManager)

	// Assert that the db.DB hasn't changed.
	// It looks like everything is the same because we're not
	// replacing `Server.Database`, and we're not changing the
	// underlying pointer to *dbw.DB either.
	// We're actually replacing the value of `wrapped` (*dbw.DB)
	// in-place (without changing memory addr).
	// Since we can't access `db.DB.wrapped` here, that has to be
	// tested separately on the appropriate package.
	if oldDB != cmd.Server.Database {
		t.Fatalf("server *db.DB pointers differ, expected equal. old ptr %p | new ptr %p", oldDB, cmd.Server.Database)
	}
	require.EqualValues(t, oldDB, cmd.Server.Database)

	// Wait for the old connection to be closed
	time.Sleep(db.CloseSwappedDbDuration)

	// `sqlDB` still points to database A here. Assert that the object
	// is Closed.
	row = sqlDB.QueryRow("select 1")
	require.ErrorContains(t, row.Err(), "database is closed")

	// Get underlying *sql.DB again. We only need to do this on the test
	// because we're getting a pointer to a *sql.DB to call Query directly
	// and we swap the database at a higher level.
	// At this point `sqlDB` is pointing to a memory address containing
	// the *sql.DB used for db A, so we need to call the function again
	// to update that reference.
	sqlDB, err = cmd.Server.Database.SqlDB(context.Background())
	require.NoError(t, err)
	require.NotNil(t, sqlDB)

	// Assert we're connected to database B.
	row = sqlDB.QueryRow("select current_database();")
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&currentDB))
	require.Equal(t, dbNameB, currentDB)

	// Assert the lock on database A has been released.
	row = sqlDB.QueryRow(getDatabaseLockQuery, dbNameA)
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&lock))
	require.Equal(t, 0, lock)

	// Assert we've grabbed a lock on database B.
	row = sqlDB.QueryRow(getDatabaseLockQuery, dbNameB)
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&lock))
	require.Equal(t, 1, lock)

	cmd.ShutdownCh <- struct{}{}
	wg.Wait()
}

func TestReloadControllerDatabase_InvalidNewDatabaseState(t *testing.T) {
	td := t.TempDir()

	// Create and migrate database A and B.
	controllerKey := config.DevKeyGeneration()

	closeA, urlA, dbNameA, err := getInitDatabase(t, controllerKey)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeA()) })

	invalidDatabaseClose, invalidDatabaseUrl, _, err := dbtest.StartUsingTemplate("postgres") // no kms set-up.
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, invalidDatabaseClose()) })

	cmd := testServerCommand(t, testServerCommandOpts{})

	workerAuthKey := config.DevKeyGeneration()
	recoveryKey := config.DevKeyGeneration()
	cfgHcl := fmt.Sprintf(dbSwapConfig, urlA, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	earlyExitChan := make(chan struct{})
	go func() {
		defer wg.Done()

		args := []string{"-config", td + "/config.hcl"}
		exitCode := cmd.Run(args)
		if exitCode != 0 {
			output := cmd.UI.(*cli.MockUi).ErrorWriter.String() + cmd.UI.(*cli.MockUi).OutputWriter.String()
			fmt.Printf("%s: got a non-zero exit status: %s", t.Name(), output)
		}
		select {
		case earlyExitChan <- struct{}{}:
		default:
		}
	}()

	// Wait until things are up and running (or timeout).
	select {
	case <-cmd.startedCh:
	case <-earlyExitChan:
		t.Fatal("server exited early")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server to start")
	}

	require.NotNil(t, cmd.schemaManager)

	sqlDB, err := cmd.Server.Database.SqlDB(context.Background())
	require.NoError(t, err)
	require.NotNil(t, sqlDB)

	// Assert we're connected to database A.
	var currentDB string
	row := sqlDB.QueryRow("select current_database();")
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&currentDB))
	require.Equal(t, dbNameA, currentDB)

	// Assert we've grabbed a lock on database A.
	var lock int
	row = sqlDB.QueryRow(getDatabaseLockQuery, dbNameA)
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&lock))
	require.Equal(t, 1, lock)

	// Get old values so we can test against them later.
	oldSchemaManager := cmd.schemaManager

	// Change config and SIGHUP.
	cfgHcl = fmt.Sprintf(dbSwapConfig, invalidDatabaseUrl, controllerKey, workerAuthKey, recoveryKey)
	require.NoError(t, os.WriteFile(td+"/config.hcl", []byte(cfgHcl), 0o644))

	cmd.SighupCh <- struct{}{}
	select {
	case <-cmd.reloadedCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for server reload")
	}

	// Assert that the schema manager ptr and value did not change.
	if oldSchemaManager != cmd.schemaManager {
		t.Fatalf("schema manager pointers are different (old: %p / new: %p). expected equal", oldSchemaManager, cmd.schemaManager)
	}
	require.EqualValues(t, oldSchemaManager, cmd.schemaManager)

	// Assert we're still connected to and locked on database A.
	sqlDB, err = cmd.Server.Database.SqlDB(context.Background())
	require.NoError(t, err)
	require.NotNil(t, sqlDB)

	row = sqlDB.QueryRow("select current_database();")
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&currentDB))
	require.Equal(t, dbNameA, currentDB)

	row = sqlDB.QueryRow(getDatabaseLockQuery, dbNameA)
	require.NoError(t, row.Err())
	require.NoError(t, row.Scan(&lock))
	require.Equal(t, 1, lock)

	cmd.ShutdownCh <- struct{}{}
	wg.Wait()
}

func TestReloadControllerDatabase_VariousNilValues(t *testing.T) {
	// There's not much we can test in these cases, however
	// we can ensure things don't panic.
	tests := []struct {
		name      string
		cmd       *Command
		newConfig *config.Config
	}{
		{
			name: "nilServer",
			cmd: &Command{
				Server:     nil,
				controller: &controller.Controller{},
				Config: &config.Config{
					Controller: &config.Controller{
						Database: &config.Database{Url: "db_url"},
					},
				},
			},
			newConfig: &config.Config{
				Controller: &config.Controller{
					Database: &config.Database{Url: "db_url_new"},
				},
			},
		},
		{
			name: "nilServerDatabase",
			cmd: &Command{
				Server:     &base.Server{Database: nil},
				controller: &controller.Controller{},
				Config: &config.Config{
					Controller: &config.Controller{
						Database: &config.Database{Url: "db_url"},
					},
				},
			},
			newConfig: &config.Config{
				Controller: &config.Controller{
					Database: &config.Database{Url: "db_url_new"},
				},
			},
		},
		{
			name: "nilController",
			cmd: &Command{
				Server:     &base.Server{Database: &db.DB{}},
				controller: nil,
				Config: &config.Config{
					Controller: &config.Controller{
						Database: &config.Database{Url: "db_url"},
					},
				},
			},
			newConfig: &config.Config{
				Controller: &config.Controller{
					Database: &config.Database{Url: "db_url_new"},
				},
			},
		},
		{
			name: "nilNewConfig",
			cmd: &Command{
				Server:     &base.Server{Database: &db.DB{}},
				controller: &controller.Controller{},
				Config: &config.Config{
					Controller: &config.Controller{
						Database: &config.Database{Url: "db_url"},
					},
				},
			},
			newConfig: nil,
		},
		{
			name: "nilNewConfigController",
			cmd: &Command{
				Server:     &base.Server{Database: &db.DB{}},
				controller: &controller.Controller{},
				Config: &config.Config{
					Controller: &config.Controller{
						Database: &config.Database{Url: "db_url"},
					},
				},
			},
			newConfig: &config.Config{Controller: nil},
		},
		{
			name: "nilNewConfigControllerDatabase",
			cmd: &Command{
				Server:     &base.Server{Database: &db.DB{}},
				controller: &controller.Controller{},
				Config: &config.Config{
					Controller: &config.Controller{
						Database: &config.Database{Url: "db_url"},
					},
				},
			},
			newConfig: &config.Config{
				Controller: &config.Controller{Database: nil},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				require.NoError(t, tt.cmd.reloadControllerDatabase(tt.newConfig))
			})
		})
	}
}

// getInitDatabase creates a database and sets the KMS up.
func getInitDatabase(t *testing.T, kmsRootKey string) (func() error, string, string, error) {
	close, url, dbName, err := dbtest.StartUsingTemplate("postgres")
	require.NoError(t, err)

	cmd := testServerCommand(t, testServerCommandOpts{})
	cmd.Server.DatabaseUrl = url

	kmsConfig := fmt.Sprintf(`
	kms "aead" {
		purpose = "root"
		aead_type = "aes-gcm"
		key = "%s"
		key_id = "global_root"
	}`, kmsRootKey)

	cfg, err := config.Parse(kmsConfig)
	require.NoError(t, err)
	require.NoError(t, cmd.SetupKMSes(context.Background(), cli.NewMockUi(), cfg))

	require.NoError(t, cmd.Server.OpenAndSetServerDatabase(context.Background(), "postgres"))
	require.NoError(t, cmd.Server.CreateGlobalKmsKeys(context.Background()))

	return close, url, dbName, err
}
