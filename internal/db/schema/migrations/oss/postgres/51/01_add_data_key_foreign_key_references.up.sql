begin;

  alter table auth_token
    add constraint kms_data_key_version_fkey
      foreign key (key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

  alter table auth_password_argon2_cred
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
    add constraint kms_data_key_version_fkey
      foreign key (key_id)
        references kms_data_key_version (private_id)
        on delete restrict
        on update cascade;

commit;
