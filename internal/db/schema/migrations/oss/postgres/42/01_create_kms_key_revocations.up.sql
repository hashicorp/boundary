begin;

    create table kms_key_revocation_status_enm (
        string text primary key
            constraint only_predefined_values_allowed
            check(string in ('pending', 'running', 'completed', 'failed'))
    );

    comment on table kms_key_revocation_status_enm is
        'Table holding valid statuses a key revocation can take';

    insert into kms_key_revocation_status_enm (string)
    values
        ('pending'),
        ('running'),
        ('completed'),
        ('failed');

    create trigger 
        mmutable_columns
    before
    update on kms_key_revocation_status_enm
        for each row execute procedure immutable_columns('string');

    create table kms_key_revocations(
        private_id wt_private_id primary key,
        key_id wt_private_id not null,
        create_time wt_timestamp not null,
        status text not null
            references kms_key_revocation_status_enm(string),
        end_time wt_timestamp null default null
    );

    comment on table kms_key_revocations is
        'Table holding historical, current and pending key revocations';

    create trigger
        immutable_columns
    before
    update on kms_key_revocations
        for each row execute procedure immutable_columns('private_id', 'key_id', 'create_time');
    
commit;
