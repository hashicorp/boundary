package oplog

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/watchtower/internal/db/timestamp"
	"github.com/hashicorp/watchtower/internal/oplog/oplog_test"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_ImmutableFields(t *testing.T) {

	cleanup, db := setup(t)
	defer testCleanup(t, cleanup, db)
	cipherer := testWrapper(t)

	writer := &GormWriter{db}
	id := testId(t)
	u := oplog_test.TestUser{
		Name: "foo-" + id,
	}
	t.Log(&u)

	id2 := testId(t)
	u2 := oplog_test.TestUser{
		Name: "foo-" + id2,
	}
	t.Log(&u2)

	ticketer, err := NewGormTicketer(db, WithAggregateNames(true))
	require.NoError(t, err)

	ticket, err := ticketer.GetTicket("default")
	require.NoError(t, err)

	new, err := NewEntry(
		"test-users",
		Metadata{
			"key-only":   nil,
			"deployment": []string{"amex"},
			"project":    []string{"central-info-systems", "local-info-systems"},
		},
		cipherer,
		ticketer,
	)
	require.NoError(t, err)
	err = new.WriteEntryWith(context.Background(), writer, ticket,
		&Message{Message: &u, TypeName: "user", OpType: OpType_OP_TYPE_CREATE},
		&Message{Message: &u2, TypeName: "user", OpType: OpType_OP_TYPE_CREATE})
	require.NoError(t, err)

	future, err := ptypes.TimestampProto(time.Now().Add(time.Hour))
	require.NoError(t, err)

	var tests = []struct {
		name      string
		update    *Entry
		fieldMask []string
	}{
		{
			name:      "update id",
			update:    func() *Entry { e := testCloneEntry(new); e.Id = 11111111; return e }(),
			fieldMask: []string{"Id"},
		},
		{
			name: "update update_time",
			update: func() *Entry {
				e := testCloneEntry(new)
				e.UpdateTime = &timestamp.Timestamp{Timestamp: future}
				return e
			}(),
			fieldMask: []string{"UpdateTime"},
		},
		{
			name: "update create_time",
			update: func() *Entry {
				e := testCloneEntry(new)
				e.CreateTime = &timestamp.Timestamp{Timestamp: future}
				return e
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "update create_time",
			update: func() *Entry {
				e := testCloneEntry(new)
				e.Version = "867-5309"
				return e
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "update create_time",
			update: func() *Entry {
				e := testCloneEntry(new)
				e.AggregateName = "Jenny"
				return e
			}(),
			fieldMask: []string{"AggregateName"},
		},
		{
			name: "update data",
			update: func() *Entry {
				e := testCloneEntry(new)
				// CtData is the field sent to the db.
				e.CtData = []byte("Lorem Ipsum")
				return e
			}(),
			fieldMask: []string{"CtData"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := testCloneEntry(new)
			err = db.First(orig).Error
			require.NoError(err)

			err := writer.Update(tt.update, tt.fieldMask, nil)
			require.Error(err)

			after := testCloneEntry(new)
			err = db.First(&after).Error
			require.NoError(err)

			assert.True(proto.Equal(orig, after))

		})
	}
}

func testCloneEntry(e *Entry) *Entry {
	cp := proto.Clone(e.Entry)
	return &Entry{
		Entry: cp.(*store.Entry),
	}
}
