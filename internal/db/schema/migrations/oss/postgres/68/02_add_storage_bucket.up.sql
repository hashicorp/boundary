-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
  
  -- Stub for storage plugin storage bucket table
  create table storage_plugin_storage_bucket (
    public_id wt_public_id primary key,
    worker_filter wt_bexprfilter not null
  );

  -- Stub for storage bucket table
  create table storage_bucket (
    public_id wt_public_id primary key,
    scope_id wt_scope_id
      constraint iam_scope_fkey
        references iam_scope (public_id)
        on delete restrict -- Scopes with storage buckets cannot be deleted
        on update cascade
  );

commit;
