begin;

  create table credential_vault_library_user_password_map (
    private_id wt_private_id,
    library_id wt_public_id,
    primary key (private_id, library_id),
    constraint credential_vault_library_map_fk
      foreign key (private_id, library_id)
      references credential_vault_library_map (private_id, library_id)
      on delete cascade
      on update cascade,
    constraint credential_vault_library_user_password_map_library_id_uq
      unique(library_id),
    username text not null
      constraint username_must_not_be_empty
        check(length(trim(username)) > 0),
    password text not null
      constraint password_must_not_be_empty
        check(length(trim(password)) > 0)
  );
  comment on table credential_vault_library_user_password_map is
    'credential_vault_library_user_password_map is a table '
    'where each row represents a mapping from a generic vault secret to a user password credential type '
    'for a vault credential library.';

  create trigger immutable_columns before update on credential_vault_library_user_password_map
    for each row execute procedure immutable_columns('private_id', 'library_id');

  create trigger insert_credential_vault_library_map_subtype before insert on credential_vault_library_user_password_map
    for each row execute procedure insert_credential_vault_library_map_subtype();

  create trigger delete_credential_vault_library_map_subtype after delete on credential_vault_library_user_password_map
    for each row execute procedure delete_credential_vault_library_map_subtype();

commit;
