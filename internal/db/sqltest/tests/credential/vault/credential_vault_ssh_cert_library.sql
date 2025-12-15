-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(16);
  select wtt_load('widgets', 'iam', 'kms', 'auth', 'hosts', 'targets', 'credentials');

  -- validate default values
  prepare insert_valid as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type,  key_bits)
    values
      ('vs_______wvs', 'vl______vsc1', '/ssh/sign/foo', 'bar',    'ed25519', 0),
      ('vs_______wvs', 'vl______vsc2', '/ssh/sign/foo', 'bar',    'ecdsa',   256),
      ('vs_______wvs', 'vl______vsc3', '/ssh/sign/foo', 'bar',    'ecdsa',   384),
      ('vs_______wvs', 'vl______vsc4', '/ssh/sign/foo', 'bar',    'ecdsa',   521),
      ('vs_______wvs', 'vl______vsc5', '/ssh/sign/foo', 'bar',    'rsa',     2048),
      ('vs_______wvs', 'vl______vsc6', '/ssh/sign/foo', 'bar',    'rsa',     3072),
      ('vs_______wvs', 'vl______vsc7', '/ssh/sign/foo', 'bar',    'rsa',     4096);

  prepare select_vault_ssh_cert_libraries as
    select public_id::text, store_id::text, name::text, description::text, vault_path, username, key_type, key_bits, ttl, key_id, critical_options, extensions, credential_type, project_id::text
    from credential_vault_ssh_cert_library
    where public_id like 'vl______vsc%'
    order by public_id;

  prepare select_libraries as
    select public_id::text, store_id::text, credential_type, project_id::text
    from credential_library
    where public_id in ('vl______vsc1', 'vl______vsc3')
    order by public_id;

  select lives_ok('insert_valid');
  select results_eq(
    'select_vault_ssh_cert_libraries',
    $$VALUES
      ('vl______vsc1', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ed25519', 0,    null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc2', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ecdsa',   256,  null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc3', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ecdsa',   384,  null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc4', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ecdsa',   521,  null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc5', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'rsa',     2048, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc6', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'rsa',     3072, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc7', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'rsa',     4096, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget')$$
  );


  prepare insert_invalid_key_type as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc8', '/ssh/sign/foo', 'bar', 'unknown', 256);
	select throws_ok('insert_invalid_key_type', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_valid_key_type_key_bits_fkey"');

  prepare insert_invalid_key_bits as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc8', '/ssh/sign/foo', 'bar',    'rsa',    99);
	select throws_ok('insert_invalid_key_bits', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_valid_key_type_key_bits_fkey"');

  prepare insert_invalid_rsa_key_type_bits_combo as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc8', '/ssh/sign/foo', 'bar',    'rsa',    384);
	select throws_ok('insert_invalid_rsa_key_type_bits_combo', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_valid_key_type_key_bits_fkey"');

  prepare insert_invalid_ecdsa_key_type_bits_combo as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc8', '/ssh/sign/foo', 'bar',    'ecdsa',    2048);
	select throws_ok('insert_invalid_ecdsa_key_type_bits_combo', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_valid_key_type_key_bits_fkey"');

  prepare insert_invalid_ed25519_key_type_bits_combo as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc8', '/ssh/sign/foo', 'bar',    'ed25519',    2048);
	select throws_ok('insert_invalid_ed25519_key_type_bits_combo', 'insert or update on table "credential_vault_ssh_cert_library" violates foreign key constraint "credential_vault_ssh_cert_valid_key_type_key_bits_fkey"');

  prepare insert_invalid_vault_path as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path, username, key_type,  key_bits)
    values
      ('vs_______wvs', 'vl______vsc8', '/ssh/not-sign/foo',         'bar',    'ed25519', 0);
	select throws_ok('insert_invalid_vault_path', 'new row for relation "credential_vault_ssh_cert_library" violates check constraint "vault_path_must_be_sign_or_issue"');

  prepare insert_invalid_vault_path_empty as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path, username, key_type,  key_bits)
    values
      ('vs_______wvs', 'vl______vsc8', '',         'bar',    'ed25519', 0);
	select throws_ok('insert_invalid_vault_path', 'new row for relation "credential_vault_ssh_cert_library" violates check constraint "vault_path_must_be_sign_or_issue"');

  prepare insert_invalid_username as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, key_type,  key_bits)
    values
      ('vs_______wvs', 'vl______vsc8', '/ssh/sign/foo', '',       'ed25519', 0);
	select throws_ok('insert_invalid_username', 'new row for relation "credential_vault_ssh_cert_library" violates check constraint "username_must_not_be_empty"');

  prepare insert_invalid_credential_type as
    insert into credential_vault_ssh_cert_library
      (store_id,       public_id,      vault_path,      username, credential_type, key_type, key_bits)
    values
      ('vs_______wvs', 'vl______vsc8', '/ssh/sign/foo', 'bar',    'username_password', 'ed25519', 0);
	select lives_ok('insert_invalid_credential_type');
  select results_eq(
    'select_vault_ssh_cert_libraries',
    $$VALUES
      ('vl______vsc1', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ed25519', 0,    null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc2', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ecdsa',   256,  null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc3', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ecdsa',   384,  null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc4', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ecdsa',   521,  null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc5', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'rsa',     2048, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc6', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'rsa',     3072, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc7', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'rsa',     4096, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc8', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ed25519', 0,    null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget')$$
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
      ('vl______vsc1', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ed25519', 0,    null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc2', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ecdsa',   256,  null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc4', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ecdsa',   521,  null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc5', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'rsa',     2048, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc6', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'rsa',     3072, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc7', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'rsa',     4096, null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget'),
      ('vl______vsc8', 'vs_______wvs', null, null, '/ssh/sign/foo', 'bar', 'ed25519', 0,    null, null, null::bytea, null::bytea, 'ssh_certificate', 'p____bwidget')$$
  );

  select results_eq(
    'select_libraries',
    $$VALUES
      ('vl______vsc1', 'vs_______wvs', 'ssh_certificate', 'p____bwidget')$$
  );

rollback;
