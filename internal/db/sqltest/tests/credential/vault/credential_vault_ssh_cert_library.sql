begin;
  select plan(15);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate default values
  prepare insert_using_defaults as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username)
    values
      ('vs_______wvs', 'vl______vsc1', '/ssh/sign/foo', 'bar');

  prepare select_vault_ssh_cert_libraries as
    select public_id::text, store_id::text, name::text, description::text, vault_path, username, key_type, key_bits, ttl, key_id, critical_options, extensions, credential_type, project_id::text
    from credential_vault_ssh_cert_library
    where public_id in ('vl______vsc1', 'vl______vsc3')
    order by public_id;

  prepare select_libraries as
    select public_id::text, store_id::text, credential_type, project_id::text
    from credential_library
    where public_id in ('vl______vsc1', 'vl______vsc3')
    order by public_id;

  select lives_ok('insert_using_defaults');
  select results_eq(
    'select_vault_ssh_cert_libraries',
    $$VALUES
      ('vl______vsc1', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ed25519', 0, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget')$$
  );

  prepare insert_invalid_key_type as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type)
    values
      ('vs_______wvs', 'vl______vsc2', '/ssh/sign/foo', 'bar', 'unknown');
	select throws_ok('insert_invalid_key_type', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_key_type_enm_fkey"');

  prepare insert_invalid_key_bits as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc2', '/ssh/sign/foo', 'bar',    'rsa',    99);
	select throws_ok('insert_invalid_key_bits', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_key_bits_enm_fkey"');

  prepare insert_invalid_rsa_key_type_bits_combo as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc2', '/ssh/sign/foo', 'bar',    'rsa',    384);
	select throws_ok('insert_invalid_rsa_key_type_bits_combo', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_valid_key_type_key_bits_fkey"');

  prepare insert_invalid_ecdsa_key_type_bits_combo as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc2', '/ssh/sign/foo', 'bar',    'ecdsa',    2048);
	select throws_ok('insert_invalid_ecdsa_key_type_bits_combo', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_valid_key_type_key_bits_fkey"');

  prepare insert_invalid_ed25519_key_type_bits_combo as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc2', '/ssh/sign/foo', 'bar',    'ed25519',    2048);
	select throws_ok('insert_invalid_ed25519_key_type_bits_combo', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_valid_key_type_key_bits_fkey"');

  prepare insert_invalid_vault_path as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username)
    values
      ('vs_______wvs', 'vl______vsc2', '', 'bar');
	select throws_ok('insert_invalid_vault_path', 'new row for relation "credential_vault_ssh_cert_library" violates check constraint "vault_path_must_not_be_empty"');

  prepare insert_invalid_username as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username)
    values
      ('vs_______wvs', 'vl______vsc2', '/ssh/sign/foo', '');
	select throws_ok('insert_invalid_username', 'new row for relation "credential_vault_ssh_cert_library" violates check constraint "username_must_not_be_empty"');

  prepare insert_invalid_credential_type as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, credential_type)
    values
      ('vs_______wvs', 'vl______vsc3', '/ssh/sign/foo', 'bar',    'username_password');
	select lives_ok('insert_invalid_credential_type');
  select results_eq(
    'select_vault_ssh_cert_libraries',
    $$VALUES
      ('vl______vsc1', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ed25519', 0, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc3', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ed25519', 0, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget')$$
  );

  select results_eq(
    'select_libraries',
    $$VALUES
      ('vl______vsc1', 'vs_______wvs', 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc3', 'vs_______wvs', 'ssh_certificate', 'p____bwidget')$$
  );

  prepare delete_ssh_cred_library as
    delete from credential_vault_ssh_cert_library where public_id = 'vl______vsc3';

  select lives_ok('delete_ssh_cred_library');
  select results_eq(
    'select_vault_ssh_cert_libraries',
    $$VALUES
      ('vl______vsc1', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ed25519', 0, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget')$$
  );

  select results_eq(
    'select_libraries',
    $$VALUES
      ('vl______vsc1', 'vs_______wvs', 'ssh_certificate', 'p____bwidget')$$
  );

rollback;
