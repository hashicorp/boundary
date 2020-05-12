package iam

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/oplog/store"
)

// TestVerifyOplog will verify that there is an oplog entry
func TestVerifyOplog(r db.Reader, resourcePublicId string, opt ...Option) error {
	opts := getOpts(opt...)
	withOperation := opts.withOperation
	withCreateNbf := opts.withCreateNbf

	var metadata store.Metadata

	where := "key = 'resource-public-id' and value = ?"
	args := []interface{}{
		resourcePublicId,
	}

	if withOperation != oplog.OpType_OP_TYPE_UNSPECIFIED {
		where = where + ` and entry_id in (
			select entry_id
			FROM oplog_metadata
			where
			 	key = 'op-type' and
				 value = ?
			 )`
		args = append(args, strconv.Itoa(int(withOperation)))
	}

	if withCreateNbf != nil {
		where = fmt.Sprintf("%s and create_time > NOW()::timestamp - interval '%d second'", where, *withCreateNbf)
	}

	if err := r.LookupWhere(context.Background(), &metadata, where, args...); err != nil {
		return err
	}

	var foundEntry oplog.Entry
	if err := r.LookupWhere(
		context.Background(),
		&foundEntry,
		"id = ?",
		metadata.EntryId,
	); err != nil {
		return err
	}
	return nil
}
