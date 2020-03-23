package oplog

// Replayable defines an interface for messages that can be replayed from the oplog entries.  we need to be
// able to replay into different table names.
type ReplayableMessage interface {
	TableName() string
	SetTableName(name string)
}
