-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  alter table wh_credential_group_membership
    add primary key (credential_group_key, credential_key);

commit;
