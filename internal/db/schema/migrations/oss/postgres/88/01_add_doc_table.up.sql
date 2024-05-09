-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

create extension if not exists vector;

create table doc (
    id uuid primary key default gen_random_uuid(),
    path text not null unique,
    content text not null,
    embedding vector not null
);

commit;
