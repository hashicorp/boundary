package schema

import (
	"testing"
)

// Creates a new migrationState only with the versions <= the provided maxVer
func TestCreatePartialMigrationState(om migrationState, maxVer int) migrationState {
	nState := migrationState{
		upMigrations: make(map[int][]byte),
	}
	for k := range om.upMigrations {
		if k > maxVer {
			// Don't store any versions past our test version.
			continue
		}
		nState.upMigrations[k] = om.upMigrations[k]
		if nState.binarySchemaVersion < k {
			nState.binarySchemaVersion = k
		}
	}
	return nState
}

func TestCloneMigrationStates(t *testing.T) map[string]migrationState {
	return cloneMigrationStates(migrationStates)
}
