-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

alter table auth_oidc_account
  add column token_claims text
  constraint token_claims_must_not_be_empty
  check(
    length(trim(token_claims)) > 0
  );
alter table auth_oidc_account
  add column userinfo_claims text
  constraint userinfo_claims_must_not_be_empty
  check(
    length(trim(userinfo_claims)) > 0
  );

commit;