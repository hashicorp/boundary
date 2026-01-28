-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  drop trigger  default_ssh_certificate_credential_type on credential_vault_ssh_cert_library;
  drop function default_ssh_certificate_credential_type;

  -- Replaces trigger in 63/01_credential_vault_ssh_cert_library.up.sql
  create function default_ssh_certificate_credential_type() returns trigger
  as $$
  begin
    if new.credential_type is distinct from 'ssh_certificate' then
      new.credential_type = 'ssh_certificate';
    end if;
    return new;
  end;
  $$ language plpgsql;
  comment on function default_ssh_certificate_credential_type is
    'default_ssh_certificate_credential_type ensures the credential_type is set to ssh_certificate';

  create trigger default_ssh_certificate_credential_type before insert on credential_vault_ssh_cert_library
    for each row execute procedure default_ssh_certificate_credential_type();
commit;
