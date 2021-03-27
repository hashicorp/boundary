package migration

import (
	"database/sql"
	"testing"
)

func Test_PrimaryAuthMethod(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tx   *sql.Tx
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		})
	}
}

func Test_setPrimaryAuthMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tx   *sql.Tx
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		})
	}
}

func Test_findScopesWithNoPrimary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tx   *sql.Tx
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		})
	}
}
