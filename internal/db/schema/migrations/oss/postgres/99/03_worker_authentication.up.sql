begin;

create table worker_auth_operational_indicator_enm(
  state text primary key
    constraint only_predefined_worker_auth_states_allowed
      check (
          state in ('next','current')
        )
);

comment on table worker_auth_operational_indicator_enm is
  'worker_auth_operational_indicator_enm is an enumeration table representing the state of certificates used for worker authentication.';

insert into worker_auth_operational_indicator_enm (state)
values
  ('next'),
  ('current');

create table worker_auth_ca_certificate(
 serial_number numeric,
 certificate  bytea not null
   constraint certificate_must_not_be_empty
     check(length(certificate) > 0),
 not_valid_before  wt_timestamp not null,
 not_valid_after  wt_timestamp not null
   constraint not_valid_before_must_be_before_not_valid_after
     check(not_valid_before < not_valid_after),
 public_key bytea primary key
   constraint public_key_must_not_be_empty
     check(length(public_key) > 0),
 private_key bytea not null -- encrypted PEM encoded private key
   constraint private_key_must_not_be_empty
     check(length(private_key) > 0),
 key_id kms_private_id not null -- key used to encrypt entries via wrapping wrapper.
   constraint kms_data_key_version_fkey
     references kms_data_key_version (private_id)
     on delete restrict
     on update cascade,
 state text unique not null
   constraint worker_auth_operational_indicator_enm_fkey
     references worker_auth_operational_indicator_enm(state)
       on delete restrict
       on update cascade
);

comment on table worker_auth_ca_certificate is
  'worker_auth_ca_certificate is a table where each row represents a root certificate for used for worker authentication.';

create table worker_auth_authorized(
  worker_key_identifier text primary key, -- The public key id for this WorkerAuth entry, generated from the signing pub key
  worker_id wt_public_id not null
    constraint server_worker_fkey
      references server_worker (public_id)
        on delete cascade
        on update cascade,
  worker_signing_pub_key bytea not null
    constraint worker_signing_pub_key_must_not_be_empty
      check(length(worker_signing_pub_key) > 0),
  worker_encryption_pub_key bytea not null
    constraint worker_encryption_pub_key_must_not_be_empty
      check(length(worker_encryption_pub_key) > 0),
  controller_encryption_priv_key bytea not null -- encrypted PEM encoded private key
    constraint controller_encryption_priv_key_must_not_be_empty
      check(length(controller_encryption_priv_key) > 0),
  key_id kms_private_id not null -- key used to encrypt entries via wrapping wrapper.
    constraint kms_data_key_version_fkey
      references kms_data_key_version (private_id)
      on delete restrict
      on update cascade,
  nonce bytea
);

comment on table worker_auth_authorized is
  'worker_auth_authorized is a table where each row represents key and cert data associated with an authorized worker.';

create table worker_auth_certificate_bundle(
 certificate_public_key bytea not null
   constraint worker_auth_ca_certificate_fkey
     references worker_auth_ca_certificate(public_key)
     on delete cascade
     on update cascade,
 worker_key_identifier text not null
   constraint worker_auth_authorized_fkey
     references worker_auth_authorized(worker_key_identifier)
     on delete cascade
     on update cascade,
 cert_bundle bytea
   constraint current_cert_bundle_must_not_be_empty
     check(length(cert_bundle) > 0),
 primary key(certificate_public_key, worker_key_identifier)
);

comment on table worker_auth_certificate_bundle is
  'worker_auth_certificate_bundle is a table where each row represents a cert bundle issued by a ca certificate for a worker.';

commit;