// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cleanup

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/util"
)

// RegisterJob registers the cleanup job with the provided scheduler.
func RegisterJob(ctx context.Context, s *scheduler.Scheduler, r db.Reader, w db.Writer) error {
	const op = "cleanup.RegisterJob"
	if s == nil {
		return errors.New(ctx, errors.InvalidParameter, "nil scheduler", op, errors.WithoutEvent())
	}
	if util.IsNil(r) {
		return errors.New(ctx, errors.Internal, "nil DB reader", op, errors.WithoutEvent())
	}
	if util.IsNil(w) {
		return errors.New(ctx, errors.Internal, "nil DB writer", op, errors.WithoutEvent())
	}

	cleanupJob, err := newCleanupJob(ctx, r, w)
	if err != nil {
		return fmt.Errorf("error creating cleanup job: %w", err)
	}
	if err := s.RegisterJob(ctx, cleanupJob); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

//-- function
//create or replace function insert_deleted_target() returns trigger
//as $$
//begin
//insert into target_deleted (public_id, delete_time)
//values (old.public_id, now());
//
//return old;
//end;
//$$ language plpgsql;
//comment on function insert_deleted_target is
//'insert_deleted_target will automatically insert any deleted target id from X
//into the table target_deleted';
//
//-- trigger
//create trigger trigger_insert_deleted_target before delete on target
//for each row execute function insert_deleted_target();

// create table target_deleted (public_id wt_public_id primary key, delete_time wt_timestamp);
// create or replace function insert_deleted_target() returns trigger as $$ begin insert into target_deleted (public_id, delete_time) values (old.public_id, now()); return old; end; $$ language plpgsql;
// create trigger trigger_insert_deleted_target before delete on target for each row execute function insert_deleted_target();
