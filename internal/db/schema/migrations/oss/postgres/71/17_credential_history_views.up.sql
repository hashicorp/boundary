-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- Static Credentials
create view credential_static_json_credential_hst_aggregate as
select
  rsc.recording_id,
  sjc.public_id,
  sjc.name,
  sjc.description,
  sjc.object_hmac,
  css.public_id as store_public_id,
  css.project_id as store_project_id,
  css.name as store_name,
  css.description as store_description,
  string_agg(distinct rsc.credential_purpose, '|') as purposes
from
  credential_static_json_credential_hst as sjc
  join recording_static_credential as rsc on sjc.history_id = rsc.credential_static_hst_id
  join credential_static_store_hst as css on rsc.credential_static_store_hst_id = css.history_id
group by rsc.recording_id, css.history_id, sjc.history_id;
comment on view credential_static_json_credential_hst_aggregate is
  'credential_static_json_credential_hst_aggregate contains the json credential history data along with its store and purpose data.';

create view credential_static_username_password_credential_hst_aggregate as
select
  rsc.recording_id,
  supc.public_id,
  supc.name,
  supc.description,
  supc.username,
  supc.password_hmac,
  css.public_id as store_public_id,
  css.project_id as store_project_id,
  css.name as store_name,
  css.description as store_description,
  string_agg(distinct rsc.credential_purpose, '|') as purposes
from
  credential_static_username_password_credential_hst as supc
   left join recording_static_credential as rsc on supc.history_id = rsc.credential_static_hst_id
   join credential_static_store_hst as css on rsc.credential_static_store_hst_id = css.history_id
group by supc.history_id, rsc.recording_id, css.history_id;
comment on view credential_static_username_password_credential_hst_aggregate is
  'credential_static_username_password_credential_hst_aggregate contains the username password credential history data along with its store and purpose data.';

create view credential_static_ssh_private_key_credential_hst_aggregate as
select
  rsc.recording_id,
  sspkc.public_id,
  sspkc.name,
  sspkc.description,
  sspkc.username,
  sspkc.private_key_hmac,
  sspkc.private_key_passphrase_hmac,
  css.public_id as store_public_id,
  css.project_id as store_project_id,
  css.name as store_name,
  css.description as store_description,
  string_agg(distinct rsc.credential_purpose, '|') as purposes
from credential_static_ssh_private_key_credential_hst as sspkc
   left join recording_static_credential as rsc on sspkc.history_id = rsc.credential_static_hst_id
   join credential_static_store_hst as css on rsc.credential_static_store_hst_id = css.history_id
group by sspkc.history_id, rsc.recording_id, css.history_id;
comment on view credential_static_ssh_private_key_credential_hst_aggregate is
  'credential_static_ssh_private_key_credential_hst_aggregate contains the ssh private key credential history data along with its store and purpose data.';

-- Replaced in 99/01_credential_vault_library_refactor.up.sql. Note that this
-- view's name has changed to credential_vault_generic_library_hst_aggregate.
create view credential_vault_library_hst_aggregate as
select
  rdc.recording_id,
  vl.public_id,
  vl.name,
  vl.description,
  vl.vault_path,
  vl.http_method,
  vl.http_request_body,
  vl.credential_type,
  vsh.public_id as store_public_id,
  vsh.project_id as store_project_id,
  vsh.name as store_name,
  vsh.description as store_description,
  vsh.vault_address as store_vault_address,
  vsh.namespace as store_namespace,
  vsh.tls_server_name as store_tls_server_name,
  vsh.tls_skip_verify as store_tls_skip_verify,
  vsh.worker_filter as store_worker_filter,
  string_agg(distinct rdc.credential_purpose, '|') as purposes
from credential_vault_library_hst as vl
   left join recording_dynamic_credential as rdc on vl.history_id = rdc.credential_library_hst_id
   join credential_vault_store_hst as vsh on rdc.credential_vault_store_hst_id = vsh.history_id
group by vl.history_id, rdc.recording_id, vsh.history_id;
comment on view credential_vault_library_hst_aggregate is
  'credential_vault_library_hst_aggregate contains the vault library history data along with its store and purpose data.';

create view credential_vault_ssh_cert_library_hst_aggregate as
select
  rdc.recording_id,
  vscl.public_id,
  vscl.name,
  vscl.description,
  vscl.vault_path,
  vscl.username,
  vscl.key_type,
  vscl.key_bits,
  vscl.ttl,
  vscl.critical_options,
  vscl.extensions,
  vscl.credential_type,
  vsh.public_id as store_public_id,
  vsh.project_id as store_project_id,
  vsh.name as store_name,
  vsh.description as store_description,
  vsh.vault_address as store_vault_address,
  vsh.namespace as store_namespace,
  vsh.tls_server_name as store_tls_server_name,
  vsh.tls_skip_verify as store_tls_skip_verify,
  vsh.worker_filter as store_worker_filter,
  string_agg(distinct rdc.credential_purpose, '|') as purposes
from credential_vault_ssh_cert_library_hst as vscl
   left join recording_dynamic_credential as rdc on vscl.history_id = rdc.credential_library_hst_id
   join credential_vault_store_hst as vsh on rdc.credential_vault_store_hst_id = vsh.history_id
group by vscl.history_id, rdc.recording_id, vsh.history_id;
comment on view credential_vault_ssh_cert_library_hst_aggregate is
  'credential_vault_ssh_cert_library_hst_aggregate contains the vault library history data along with its store and purpose data.';

commit;
