-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;



-- this constraint is intended to ensure that a user cannot have more than one
-- account per auth_method. 
--
-- If this constraint causes the migrations to fail the operartor can run the
-- following query to get a list of user ids which have more that one account
-- within the same auth method.  At that point, the operator will need to pick
-- which account to keep.    
----------------------------------------------------------------------------
-- with too_many_accounts(iam_user_id, acct_count) as (
--   select 
--     iam_user_id, 
--     count(*) as acct_count
--   from 	
--       auth_account 
--   group by auth_method_id, iam_user_id 
-- )
-- select 
--   *
-- from
--   too_many_accounts
-- where 
--   acct_count > 1;
alter table auth_account
  add constraint auth_account_auth_method_id_public_id_uq
    unique(auth_method_id, iam_user_id);

commit;