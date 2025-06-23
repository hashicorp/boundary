-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

create table target_proxy_certificate(
  public_id wt_public_id primary key,
  public_key bytea,
    constraint public_key_must_not_be_empty
     check(length(public_key) > 0),
  private_key_encrypted bytea not null -- encrypted PEM encoded priv key
    constraint private_key_must_not_be_empty
      check(length(private_key_encrypted) > 0),
  key_id kms_private_id not null -- key used to encrypt entries
    constraint kms_data_key_version_fkey
      references kms_data_key_version (private_id)
      on delete restrict
      on update cascade,
   target_id wt_public_id not null
     constraint target_proxy_fkey
       references target (public_id)
       on delete cascade
       on update cascade,
   certificate bytea not null
     constraint certificate_must_not_be_empty
       check(length(certificate) > 0),
   not_valid_after wt_timestamp not null,
   version wt_version,
   create_time wt_timestamp,
   update_time wt_timestamp
);

create trigger immutable_columns before update on target_proxy_certificate
  for each row execute procedure immutable_columns('public_id', 'target_id', 'create_time');

create trigger update_version_column after update on target_proxy_certificate
  for each row execute procedure update_version_column();

create trigger update_time_column before update on target_proxy_certificate
  for each row execute procedure update_time_column();

create trigger default_create_time_column before insert on target_proxy_certificate
  for each row execute procedure default_create_time();

comment on table target_proxy_certificate is
  'target_proxy_certificate is a table where each row represents a proxy certificate for a target.';

create table target_alias_proxy_certificate(
  public_id wt_public_id primary key,
  public_key bytea,
    constraint public_key_must_not_be_empty
     check(length(public_key) > 0),
  private_key_encrypted bytea not null -- encrypted PEM encoded priv key
    constraint private_key_must_not_be_empty
      check(length(private_key_encrypted) > 0),
  key_id kms_private_id not null -- key used to encrypt entries
    constraint kms_data_key_version_fkey
      references kms_data_key_version (private_id)
      on delete restrict
      on update cascade,
 target_id wt_public_id not null
   constraint target_proxy_fkey
     references target (public_id)
     on delete cascade
     on update cascade,
 alias_id wt_public_id not null,
 certificate bytea not null
   constraint certificate_must_not_be_empty
     check(length(certificate) > 0),
 not_valid_after wt_timestamp not null,
 version wt_version,
 create_time wt_timestamp,
 update_time wt_timestamp,
 constraint alias_target_fkey
   foreign key (alias_id, target_id)
     references alias_target (public_id, destination_id)
     on delete cascade
     on update cascade
);

create trigger immutable_columns before update on target_alias_proxy_certificate
  for each row execute procedure immutable_columns('public_id', 'target_id', 'create_time');

create trigger update_version_column after update on target_alias_proxy_certificate
  for each row execute procedure update_version_column();

create trigger update_time_column before update on target_alias_proxy_certificate
  for each row execute procedure update_time_column();

create trigger default_create_time_column before insert on target_alias_proxy_certificate
  for each row execute procedure default_create_time();

comment on table target_alias_proxy_certificate is
  'target_alias_proxy_certificate is a table where each row represents a proxy certificate for a target for use with an alias.';

-- To account for users updating target aliases to change either the target id, host id, or value of an alias,
-- on update to alias_target, entries in target_alias_certificate that
-- match the old target_id and alias_id will be deleted.
create function remove_target_alias_certificates_for_updated_alias() returns trigger
as $$
begin
  -- If the destination_id, host_id, and value of the alias have not changed, do nothing.
  if old.destination_id is distinct from new.destination_id or
     old.host_id        is distinct from new.host_id        or
     old.value          is distinct from new.value          then
    delete
      from target_alias_proxy_certificate
     where target_id = old.destination_id
       and alias_id  = old.public_id;
  end if;
  return new;
end;
$$ language plpgsql;

create trigger remove_target_alias_certificates_for_updated_alias before update of destination_id, host_id, value on alias_target
    for each row execute procedure remove_target_alias_certificates_for_updated_alias();

create table session_proxy_certificate(
  session_id wt_public_id not null
    constraint session_fkey
      references session (public_id)
      on delete cascade
      on update cascade,
  certificate bytea not null
    constraint certificate_must_not_be_empty
      check(length(certificate) > 0)
);

comment on table session_proxy_certificate is
  'session_proxy_certificate is a table where each row maps a certificate to a session id.';

commit;