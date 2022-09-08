begin;

  alter table auth_token
    alter column key_id type kms_private_id,
    add constraint kms_data_key_version_fkey
      foreign key (key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

  alter table auth_password_argon2_cred
    alter column key_id type kms_private_id,
    add constraint kms_data_key_version_fkey
      foreign key (key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

  -- Some existing sessions may exist with an empty key_id
  update session
     set key_id = null
   where key_id = '';

  alter table session
    -- cannot set key_id type to kms_private_id because the kms_private_id type
    -- has a 'not null' restriction and the key_id can be null in the session
    -- table.
    add constraint kms_data_key_version_fkey
      foreign key (key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

commit;
