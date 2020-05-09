package migrations

import (
	"bytes"

	"github.com/hashicorp/watchtower/internal/db/migrations/postgres"
)

var postgresMigrations = map[string]*fakeFile{
	"migrations": {
		name: "migrations",
	},
	"migrations/01_oplog.up.sql": {
		name:   "01_oplog.up.sql",
		reader: bytes.NewReader([]byte(postgres.OplogUp01)),
	},
	"migrations/02_domain_types.down.sql": {
		name:   "02_domain_types.down.sql",
		reader: bytes.NewReader([]byte(postgres.DomainTypesDown02)),
	},
	"migrations/02_domain_types.up.sql": {
		name:   "02_domain_types.up.sql",
		reader: bytes.NewReader([]byte(postgres.DomainTypesUp02)),
	},
	"migrations/03_db.down.sql": {
		name:   "03_db.down.sql",
		reader: bytes.NewReader([]byte(postgres.DbDown03)),
	},
	"migrations/03_db.up.sql": {
		name:   "03_db.up.sql",
		reader: bytes.NewReader([]byte(postgres.DbUp03)),
	},
	"migrations/04_iam.down.sql": {
		name:   "04_iam.down.sql",
		reader: bytes.NewReader([]byte(postgres.IamDown04)),
	},
	"migrations/04_iam.up.sql": {
		name:   "04_iam.up.sql",
		reader: bytes.NewReader([]byte(postgres.IamUp04)),
	},
}
