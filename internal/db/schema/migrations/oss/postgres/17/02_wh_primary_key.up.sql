-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;

  alter table wh_credential_group_membership
    add primary key (credential_group_key, credential_key);

commit;
