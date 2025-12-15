-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  create table credential_static_username_password_domain_credential(
    public_id wt_public_id primary key,
    store_id wt_public_id not null
      constraint credential_static_store_fkey
        references credential_static_store (public_id)
        on delete cascade
        on update cascade,
    project_id wt_public_id not null,
    name wt_name,
    description wt_description,
    create_time wt_timestamp,
    update_time wt_timestamp,
    version wt_version,
    username text not null
      constraint username_must_not_be_empty
        check(length(trim(username)) > 0),
    domain text not null
      constraint domain_must_not_be_empty
        check (length(domain) > 0),
    password_encrypted bytea not null
      constraint password_encrypted_must_not_be_empty
        check(length(password_encrypted) > 0),
    password_hmac bytea not null
      constraint password_hmac_must_not_be_empty
        check(length(password_hmac) > 0),
    key_id text not null
      constraint kms_data_key_version_fkey
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade,
    constraint credential_static_fkey
      foreign key (project_id, store_id,public_id)
        references credential_static (project_id, store_id,public_id)
        on delete cascade
        on update cascade,
    -- The constraint names below do not follow our naming conventions
    -- because they would be too long. The max length for identifiers
    -- in PostgreSQL is 63 characters.
    -- https://www.postgresql.org/docs/current/limits.html
    constraint credential_static_user_password_domain_cred_store_id_name_uq
      unique(store_id, name),
    constraint credential_static_user_password_domain_store_id_public_id_uq
      unique(store_id, public_id)
    );
    comment on table credential_static_username_password_domain_credential is
      'credential_static_username_password_domain_credential table where each row is a resource that represents a static username password domain credential. '
      'It is a credential_static subtype and an aggregate root.';

    create trigger update_version_column after update on credential_static_username_password_domain_credential
        for each row execute procedure update_version_column();

    create trigger update_time_column before update on credential_static_username_password_domain_credential
        for each row execute procedure update_time_column();

    create trigger update_credential_static_table_update_time before update on credential_static_username_password_domain_credential
        for each row execute procedure update_credential_static_table_update_time();

    create trigger default_create_time_column before insert on credential_static_username_password_domain_credential
        for each row execute procedure default_create_time();

    create trigger immutable_columns before update on credential_static_username_password_domain_credential
        for each row execute procedure immutable_columns('public_id', 'store_id', 'create_time', 'project_id');

    create trigger insert_credential_static_subtype before insert on credential_static_username_password_domain_credential
        for each row execute procedure insert_credential_static_subtype();

    create trigger delete_credential_static_subtype after delete on credential_static_username_password_domain_credential
        for each row execute procedure delete_credential_static_subtype();


  create table credential_static_username_password_domain_credential_hst (
    public_id wt_public_id not null,
    name wt_name,
    description wt_description,
    project_id wt_public_id not null,
    store_id wt_public_id not null,
    username text not null,
    domain text not null
      constraint domain_must_not_be_empty
        check (length(domain) > 0),
    password_hmac bytea not null,
    history_id wt_url_safe_id default wt_url_safe_id() primary key
      constraint credential_static_history_base_fkey
        references credential_static_history_base (history_id)
        on delete cascade
        on update cascade,
    valid_range tstzrange not null default tstzrange(current_timestamp, null),
    constraint credential_static_user_pass_domain_cred_hst_valid_range_excl
      exclude using gist (public_id with =, valid_range with &&)
      -- The name of this constraint does not follow our naming conventions for
      -- constraints because it would be to long.
  );
  comment on table credential_static_username_password_domain_credential_hst is
    'credential_static_username_password_domain_credential_hst is a history table where each row contains the values from a row '
    'in the credential_static_username_password_domain_credential table during the time range in the valid_range column.';

  create trigger insert_credential_static_history_subtype before insert on credential_static_username_password_domain_credential_hst
    for each row execute function insert_credential_static_history_subtype();

  create trigger delete_credential_static_history_subtype after delete on credential_static_username_password_domain_credential_hst
    for each row execute function delete_credential_static_history_subtype();

  create trigger hst_on_insert after insert on credential_static_username_password_domain_credential
    for each row execute function hst_on_insert();

  create trigger hst_on_update after update on credential_static_username_password_domain_credential
    for each row execute function hst_on_update();
    
  create trigger hst_on_delete after delete on credential_static_username_password_domain_credential
    for each row execute function hst_on_delete();


  create table credential_static_username_password_domain_credential_deleted (
    public_id wt_public_id not null
      constraint credential_static_user_pass_domain_cred_deleted_pkey primary key, -- named to avoid exceeding 63 characters
    delete_time wt_timestamp not null
  );
  comment on table credential_static_username_password_domain_credential_deleted is
    'credential_static_username_password_domain_credential_deleted holds the ID and delete_time '
    'of every deleted static username password domain credential. '
    'It is automatically trimmed of records older than 30 days by a job.';

  create trigger insert_deleted_id after delete on credential_static_username_password_domain_credential
    for each row execute function insert_deleted_id('credential_static_username_password_domain_credential_deleted');

  create index credential_static_username_password_domain_delete_time_idx on credential_static_username_password_domain_credential_deleted (delete_time);


  create view credential_static_username_password_domain_credential_hst_agg as
  select
    rsc.recording_id,
    supdc.public_id,
    supdc.name,
    supdc.description,
    supdc.username,
    supdc.domain,
    supdc.password_hmac,
    css.public_id as store_public_id,
    css.project_id as store_project_id,
    css.name as store_name,
    css.description as store_description,
    string_agg(distinct rsc.credential_purpose, '|') as purposes
  from
    credential_static_username_password_domain_credential_hst as supdc
      left join recording_static_credential as rsc on supdc.history_id = rsc.credential_static_hst_id
      join credential_static_store_hst as css on rsc.credential_static_store_hst_id = css.history_id
  group by supdc.history_id, rsc.recording_id, css.history_id;
  comment on view credential_static_username_password_domain_credential_hst_agg is
    'credential_static_username_password_domain_credential_hst_aggregate contains the username password credential history data along with its store and purpose data.';

  -- This constraint replaces the previous constraint created in 63/01_credential_vault_ssh_cert_library.up.sql
  -- This constraint is replaced in 101/01_credential_static_password_credential.up.sql
  alter table credential_type_enm
    drop constraint only_predefined_credential_types_allowed;

  alter table credential_type_enm
    add constraint only_predefined_credential_types_allowed
      check (
        name in (
          'unspecified',
          'username_password',
          'ssh_private_key',
          'ssh_certificate',
          'username_password_domain'
        )
      );

  insert into credential_type_enm (name)
    values ('username_password_domain');

-- This function replaces the previous function created in 71/14_recording_static_credential.up.sql
-- This function is replaced in 101/01_credential_static_password_credential.up.sql
create or replace function insert_recording_static_credentials() returns trigger
  as $$
  begin
    with
    session_recording(session_id, recording_id) as (
      select session_id, public_id
        from recording_session
      where session_id = new.session_id
    ),
    session_static_creds(cred_id, purpose, recording_id) as (
      select credential_static_id, credential_purpose, recording_id
        from session_credential_static
      join session_recording using (session_id)
    ),
    static_cred_history(public_id, store_id, cred_hst_id, valid_range) as (
      select public_id, store_id, history_id, valid_range
        from credential_static_json_credential_hst
      union
      select public_id, store_id, history_id, valid_range
        from credential_static_ssh_private_key_credential_hst
      union
      select public_id, store_id, history_id, valid_range
        from credential_static_username_password_credential_hst
      union
      select public_id, store_id, history_id, valid_range
        from credential_static_username_password_domain_credential_hst
    ),
    final(recording_id, cred_id, store_id, cred_hst_id, store_hst_id, cred_purpose) as (
      select ssc.recording_id, sc.public_id, sc.store_id, sc.cred_hst_id, store_hst.history_id, ssc.purpose
        from static_cred_history as sc
        join credential_static_store_hst as store_hst on sc.store_id = store_hst.public_id
          and store_hst.valid_range @> current_timestamp
        join session_static_creds as ssc on sc.public_id = ssc.cred_id
        where sc.public_id in (select cred_id from session_static_creds)
          and sc.valid_range @> current_timestamp
    )
    insert into recording_static_credential
          (recording_id, credential_static_store_hst_id, credential_static_hst_id, credential_purpose)
    select recording_id, store_hst_id, cred_hst_id, cred_purpose
      from final;

    return new;
  end;
  $$ language plpgsql;
  comment on function insert_recording_static_credentials is
    'insert_recording_static_credentials is an after insert trigger for the recording_session table.';


  insert into oplog_ticket (name, version)
    values ('credential_static_username_password_domain_credential', 1);


commit;
