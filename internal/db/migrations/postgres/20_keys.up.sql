begin;

create table kms_key_entry (
    key_id text primary key,
    key bytea not null,
    parent_key_id text references kms_key_entry(key_id) on delete cascade on update cascade,
    scope_id wt_public_id not null references iam_scope_organization(scope_id) on delete cascade on update cascade
);

commit;