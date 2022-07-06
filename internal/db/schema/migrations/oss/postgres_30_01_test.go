package oss_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/testing/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrations_KMS_Refactor(t *testing.T) {
	const (
		priorMigration   = 28002
		currentMigration = 30004
	)

	t.Parallel()
	ctx := context.Background()
	dialect := dbtest.Postgres

	c, u, _, err := dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(dbtest.Template1))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, c())
	})
	d, err := common.SqlOpen(dialect, u)
	require.NoError(t, err)

	// migration to the prior migration (before the one we want to test)
	m, err := schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": priorMigration}),
	))
	require.NoError(t, err)

	require.NoError(t, m.ApplyMigrations(ctx))
	state, err := m.CurrentState(ctx)
	require.NoError(t, err)
	want := &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   priorMigration,
				DatabaseSchemaVersion: priorMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(t, want, state)

	// get a connection
	dbType, err := db.StringToDbType(dialect)
	require.NoError(t, err)
	conn, err := db.Open(ctx, dbType, u)
	require.NoError(t, err)
	rw := db.New(conn)

	generateTestKeys(t, rw)
	// load up the current KEKs and their versions
	existingKeks := loadKeks(t, rw)
	existingKeksVersions := loadKekVersions(t, rw)

	// load up the current DEKs and their versions
	existingDeks := loadCurrentDeks(t, rw)
	existingKeyVersions := loadCurrentDekVersions(t, rw)

	// now we're ready for the migration we want to test.
	m, err = schema.NewManager(ctx, schema.Dialect(dialect), d, schema.WithEditions(
		schema.TestCreatePartialEditions(schema.Dialect(dialect), schema.PartialEditions{"oss": currentMigration}),
	))
	require.NoError(t, err)

	require.NoError(t, m.ApplyMigrations(ctx))
	state, err = m.CurrentState(ctx)
	require.NoError(t, err)
	want = &schema.State{
		Initialized: true,
		Editions: []schema.EditionState{
			{
				Name:                  "oss",
				BinarySchemaVersion:   currentMigration,
				DatabaseSchemaVersion: currentMigration,
				DatabaseSchemaState:   schema.Equal,
			},
		},
	}
	require.Equal(t, want, state)
	// Now read all the converted keys and see if we have transformed them correctly
	{
		// get a new connection
		dbType, err := db.StringToDbType(dialect)
		require.NoError(t, err)
		conn, err := db.Open(ctx, dbType, u)
		require.NoError(t, err)
		rw := db.New(conn)

		newKeks := loadKeks(t, rw)
		assert.ElementsMatch(t, newKeks, existingKeks)

		newKeksVersions := loadKekVersions(t, rw)
		assert.ElementsMatch(t, newKeksVersions, existingKeksVersions)

		newDeks := loadNewDeks(t, rw)
		assert.ElementsMatch(t, newDeks, existingDeks)

		newKeyVersions := loadNewDekVersions(t, rw)
		assert.ElementsMatch(t, newKeyVersions, existingKeyVersions)
	}
}

// we can't use the new KMS bits since all the tables have changed, so we'll
// generate a bit of test data by hand
func generateTestKeys(t *testing.T, rw *db.Db) {
	t.Helper()
	require := require.New(t)
	testCtx := context.Background()

	for i := 0; i < 10; i++ {
		k := kek{
			PrivateId: testId(t, "rk"),
			ScopeId:   testScope(t, rw).PublicId,
		}
		require.NoError(rw.Create(testCtx, &k))

		var kv kekVersion
		for i := 0; i < 2; i++ {
			kv = kekVersion{
				PrivateId: testId(t, "rkv"),
				RootKeyId: k.PrivateId,
				Version:   1 + uint32(i),
				Key:       []byte("test-key"),
			}
			require.NoError(rw.Create(testCtx, &kv))
		}

		{
			dbk := kmsDatabaseKey{
				PrivateId: testId(t, "dk"),
				RootKeyId: k.PrivateId,
			}
			require.NoError(rw.Create(testCtx, &dbk))
			dbkv := kmsDatabaseKeyVersion{
				PrivateId:        testId(t, "dkv"),
				DatabaseKeyId:    dbk.PrivateId,
				RootKeyVersionId: kv.PrivateId,
				Key:              []byte("test-key"),
				Version:          1,
			}
			require.NoError(rw.Create(testCtx, &dbkv))
		}
		{
			ak := kmsAuditKey{
				PrivateId: testId(t, "ak"),
				RootKeyId: k.PrivateId,
			}
			require.NoError(rw.Create(testCtx, &ak))
			akv := kmsAuditKeyVersion{
				PrivateId:        testId(t, "dkv"),
				AuditKeyId:       ak.PrivateId,
				RootKeyVersionId: kv.PrivateId,
				Key:              []byte("test-key"),
				Version:          1,
			}
			require.NoError(rw.Create(testCtx, &akv))
		}
		{
			oidck := kmsOidcKey{
				PrivateId: testId(t, "oidck"),
				RootKeyId: k.PrivateId,
			}
			require.NoError(rw.Create(testCtx, &oidck))
			oidckv := kmsOidcKeyVersion{
				PrivateId:        testId(t, "dkv"),
				OidcKeyId:        oidck.PrivateId,
				RootKeyVersionId: kv.PrivateId,
				Key:              []byte("test-key"),
				Version:          1,
			}
			require.NoError(rw.Create(testCtx, &oidckv))
		}
		{
			opk := kmsOplogKey{
				PrivateId: testId(t, "opk"),
				RootKeyId: k.PrivateId,
			}
			require.NoError(rw.Create(testCtx, &opk))
			opkv := kmsOplogKeyVersion{
				PrivateId:        testId(t, "dkv"),
				OplogKeyId:       opk.PrivateId,
				RootKeyVersionId: kv.PrivateId,
				Key:              []byte("test-key"),
				Version:          1,
			}
			require.NoError(rw.Create(testCtx, &opkv))
		}
		{
			sk := kmsSessionKey{
				PrivateId: testId(t, "sk"),
				RootKeyId: k.PrivateId,
			}
			require.NoError(rw.Create(testCtx, &sk))
			skv := kmsSessionKeyVersion{
				PrivateId:        testId(t, "dkv"),
				SessionKeyId:     sk.PrivateId,
				RootKeyVersionId: kv.PrivateId,
				Key:              []byte("test-key"),
				Version:          1,
			}
			require.NoError(rw.Create(testCtx, &skv))
		}
		{
			tk := kmsTokenKey{
				PrivateId: testId(t, "tk"),
				RootKeyId: k.PrivateId,
			}
			require.NoError(rw.Create(testCtx, &tk))
			tkv := kmsTokenKeyVersion{
				PrivateId:        testId(t, "dkv"),
				TokenKeyId:       tk.PrivateId,
				RootKeyVersionId: kv.PrivateId,
				Key:              []byte("test-key"),
				Version:          1,
			}
			require.NoError(rw.Create(testCtx, &tkv))
		}

	}
}

func loadKeks(t *testing.T, rw *db.Db) []kek {
	t.Helper()
	testCtx := context.Background()
	rows, err := rw.Query(testCtx, `select private_id, scope_id, create_time from kms_root_key order by private_id`, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	var keks []kek
	for rows.Next() {
		var key kek
		require.NoError(t, rw.ScanRows(context.Background(), rows, &key))
		keks = append(keks, key)
	}
	return keks
}

func loadKekVersions(t *testing.T, rw *db.Db) []kekVersion {
	t.Helper()
	testCtx := context.Background()
	rows, err := rw.Query(testCtx, `select private_id, root_key_id, version, key, create_time from kms_root_key_version order by private_id`, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	var kekVersions []kekVersion
	for rows.Next() {
		var v kekVersion
		require.NoError(t, rw.ScanRows(context.Background(), rows, &v))
		kekVersions = append(kekVersions, v)
	}
	return kekVersions
}

func loadNewDeks(t *testing.T, rw *db.Db) []dek {
	t.Helper()
	testCtx := context.Background()
	rows, err := rw.Query(testCtx, `select private_id, root_key_id, create_time, purpose from kms_data_key order by private_id`, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	var deks []dek
	for rows.Next() {
		var key dek
		require.NoError(t, rw.ScanRows(context.Background(), rows, &key))
		deks = append(deks, key)
	}
	return deks
}

func loadCurrentDeks(t *testing.T, rw *db.Db) []dek {
	t.Helper()
	testCtx := context.Background()
	var deks []dek
	for _, purpose := range []string{"audit", "database", "oidc", "oplog", "sessions", "tokens"} {
		var table string
		switch purpose {
		case "audit":
			table = "kms_audit_key"
		case "database":
			table = "kms_database_key"
		case "oidc":
			table = "kms_oidc_key"
		case "oplog":
			table = "kms_oplog_key"
		case "sessions":
			table = "kms_session_key"
		case "tokens":
			table = "kms_token_key"
		default:
			t.Fatalf("not a supported dek %q", purpose)
		}
		sql := fmt.Sprintf(`select private_id, root_key_id, create_time, '%s' as purpose from %s order by private_id`, purpose, table)
		rows, err := rw.Query(testCtx, sql, nil)
		require.NoError(t, err)
		require.NoError(t, err)
		for rows.Next() {
			var key dek
			require.NoError(t, rw.ScanRows(context.Background(), rows, &key))
			deks = append(deks, key)
		}
	}
	return deks
}

func loadNewDekVersions(t *testing.T, rw *db.Db) []dekVersion {
	t.Helper()
	testCtx := context.Background()
	rows, err := rw.Query(testCtx, `select private_id, data_key_id, root_key_version_id, version, key, create_time from kms_data_key_version order by private_id`, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	var dekVersions []dekVersion
	for rows.Next() {
		var v dekVersion
		require.NoError(t, rw.ScanRows(context.Background(), rows, &v))
		dekVersions = append(dekVersions, v)
	}
	return dekVersions
}

func loadCurrentDekVersions(t *testing.T, rw *db.Db) []dekVersion {
	t.Helper()
	testCtx := context.Background()
	var dekVersions []dekVersion
	for _, versionType := range []string{"audit", "database", "oidc", "oplog", "session", "token"} {
		var table string
		switch versionType {
		case "audit":
			table = "kms_audit_key_version"
		case "database":
			table = "kms_database_key_version"
		case "oidc":
			table = "kms_oidc_key_version"
		case "oplog":
			table = "kms_oplog_key_version"
		case "session":
			table = "kms_session_key_version"
		case "token":
			table = "kms_token_key_version"
		}
		sql := fmt.Sprintf(`select private_id, %s_key_id, root_key_version_id, key, version, create_time from %s order by private_id`, versionType, table)
		rows, err := rw.Query(testCtx, sql, nil)
		require.NoError(t, err)
		require.NoError(t, err)
		for rows.Next() {
			result := map[string]interface{}{}
			require.NoError(t, rw.ScanRows(context.Background(), rows, &result))
			var v dekVersion
			switch versionType {
			case "audit":
				v = dekVersion{
					PrivateId:        result["private_id"].(string),
					DataKeyId:        result["audit_key_id"].(string),
					RootKeyVersionId: result["root_key_version_id"].(string),
					Key:              result["key"].([]byte),
					Version:          uint32(result["version"].(int64)),
					CreateTime:       result["create_time"].(time.Time),
				}
			case "database":
				v = dekVersion{
					PrivateId:        result["private_id"].(string),
					DataKeyId:        result["database_key_id"].(string),
					RootKeyVersionId: result["root_key_version_id"].(string),
					Key:              result["key"].([]byte),
					Version:          uint32(result["version"].(int64)),
					CreateTime:       result["create_time"].(time.Time),
				}
			case "oidc":
				v = dekVersion{
					PrivateId:        result["private_id"].(string),
					DataKeyId:        result["oidc_key_id"].(string),
					RootKeyVersionId: result["root_key_version_id"].(string),
					Key:              result["key"].([]byte),
					Version:          uint32(result["version"].(int64)),
					CreateTime:       result["create_time"].(time.Time),
				}
			case "oplog":
				v = dekVersion{
					PrivateId:        result["private_id"].(string),
					DataKeyId:        result["oplog_key_id"].(string),
					RootKeyVersionId: result["root_key_version_id"].(string),
					Key:              result["key"].([]byte),
					Version:          uint32(result["version"].(int64)),
					CreateTime:       result["create_time"].(time.Time),
				}
			case "session":
				v = dekVersion{
					PrivateId:        result["private_id"].(string),
					DataKeyId:        result["session_key_id"].(string),
					RootKeyVersionId: result["root_key_version_id"].(string),
					Key:              result["key"].([]byte),
					Version:          uint32(result["version"].(int64)),
					CreateTime:       result["create_time"].(time.Time),
				}
			case "token":
				v = dekVersion{
					PrivateId:        result["private_id"].(string),
					DataKeyId:        result["token_key_id"].(string),
					RootKeyVersionId: result["root_key_version_id"].(string),
					Key:              result["key"].([]byte),
					Version:          uint32(result["version"].(int64)),
					CreateTime:       result["create_time"].(time.Time),
				}
			}
			dekVersions = append(dekVersions, v)
		}
	}
	return dekVersions
}

func testId(t testing.TB, prefix string) string {
	t.Helper()
	id, err := db.NewPublicId(prefix)
	require.NoError(t, err)
	return id
}

func testScope(t *testing.T, rw *db.Db) *iam.Scope {
	t.Helper()
	require := require.New(t)
	testCtx := context.Background()

	s, err := iam.NewOrg()
	require.NoError(err)
	s.PublicId = testId(t, "o")

	require.NoError(rw.Create(testCtx, &s))
	return s
}

type kek struct {
	PrivateId  string
	ScopeId    string
	CreateTime time.Time
}

func (*kek) TableName() string { return "kms_root_key" }

type kekVersion struct {
	PrivateId  string
	RootKeyId  string
	Version    uint32
	Key        []byte
	CreateTime time.Time
}

func (*kekVersion) TableName() string { return "kms_root_key_version" }

type dek struct {
	PrivateId  string
	RootKeyId  string
	CreateTime time.Time
	Purpose    string
}
type dekVersion struct {
	PrivateId        string
	DataKeyId        string
	RootKeyVersionId string
	Key              []byte
	Version          uint32
	CreateTime       time.Time
}

type kmsDatabaseKey struct {
	PrivateId  string
	RootKeyId  string
	CreateTime time.Time
}

func (*kmsDatabaseKey) TableName() string { return "kms_database_key" }

type kmsDatabaseKeyVersion struct {
	PrivateId        string
	DatabaseKeyId    string
	RootKeyVersionId string
	Key              []byte
	Version          uint32
	CreateTime       time.Time
}

func (*kmsDatabaseKeyVersion) TableName() string { return "kms_database_key_version" }

type kmsAuditKey struct {
	PrivateId  string
	RootKeyId  string
	CreateTime time.Time
}

func (*kmsAuditKey) TableName() string { return "kms_audit_key" }

type kmsAuditKeyVersion struct {
	PrivateId        string
	AuditKeyId       string
	RootKeyVersionId string
	Key              []byte
	Version          uint32
	CreateTime       time.Time
}

func (*kmsAuditKeyVersion) TableName() string { return "kms_audit_key_version" }

type kmsOidcKey struct {
	PrivateId  string
	RootKeyId  string
	CreateTime time.Time
}

func (*kmsOidcKey) TableName() string { return "kms_oidc_key" }

type kmsOidcKeyVersion struct {
	PrivateId        string
	OidcKeyId        string
	RootKeyVersionId string
	Key              []byte
	Version          uint32
	CreateTime       time.Time
}

func (*kmsOidcKeyVersion) TableName() string { return "kms_oidc_key_version" }

type kmsOplogKey struct {
	PrivateId  string
	RootKeyId  string
	CreateTime time.Time
}

func (*kmsOplogKey) TableName() string { return "kms_oplog_key" }

type kmsOplogKeyVersion struct {
	PrivateId        string
	OplogKeyId       string
	RootKeyVersionId string
	Key              []byte
	Version          uint32
	CreateTime       time.Time
}

func (*kmsOplogKeyVersion) TableName() string { return "kms_oplog_key_version" }

type kmsSessionKey struct {
	PrivateId  string
	RootKeyId  string
	CreateTime time.Time
}

func (*kmsSessionKey) TableName() string { return "kms_session_key" }

type kmsSessionKeyVersion struct {
	PrivateId        string
	SessionKeyId     string
	RootKeyVersionId string
	Key              []byte
	Version          uint32
	CreateTime       time.Time
}

func (*kmsSessionKeyVersion) TableName() string { return "kms_session_key_version" }

type kmsTokenKey struct {
	PrivateId  string
	RootKeyId  string
	CreateTime time.Time
}

func (*kmsTokenKey) TableName() string { return "kms_token_key" }

type kmsTokenKeyVersion struct {
	PrivateId        string
	TokenKeyId       string
	RootKeyVersionId string
	Key              []byte
	Version          uint32
	CreateTime       time.Time
}

func (*kmsTokenKeyVersion) TableName() string { return "kms_token_key_version" }
