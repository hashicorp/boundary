package target

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/go-uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func TestTcpTarget(t *testing.T, conn *gorm.DB, scopeId, name string, opt ...Option) *TcpTarget {
	t.Helper()
	opt = append(opt, WithName(name))
	opts := getOpts(opt...)
	require := require.New(t)
	rw := db.New(conn)
	target, err := NewTcpTarget(scopeId, opt...)
	require.NoError(err)
	id, err := newTcpTargetId()
	require.NoError(err)
	target.PublicId = id
	err = rw.Create(context.Background(), target)
	require.NoError(err)

	if len(opts.withHostSets) > 0 {
		newHostSets := make([]interface{}, 0, len(opts.withHostSets))
		for _, s := range opts.withHostSets {
			hostSet, err := NewTargetHostSet(target.PublicId, s)
			require.NoError(err)
			newHostSets = append(newHostSets, hostSet)
		}
		err := rw.CreateItems(context.Background(), newHostSets)
		require.NoError(err)
	}
	return target
}

func testTargetName(t *testing.T, scopeId string) string {
	t.Helper()
	return fmt.Sprintf("%s-%s", scopeId, testId(t))
}

func testId(t *testing.T) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return id
}
