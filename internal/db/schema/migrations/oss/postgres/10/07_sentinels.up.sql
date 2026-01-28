-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

update credential_vault_credential
   set external_id = concat(external_id, u&'\ffff')
 where wt_is_sentinel(external_id)
   and not starts_with(reverse(external_id), u&'\ffff');

alter domain wt_sentinel
    drop constraint wt_sentinel_not_valid;

drop function wt_is_sentinel;

create function wt_is_sentinel(string text) returns bool
as $$
select starts_with(string, u&'\fffe') and starts_with(reverse(string), u&'\ffff');
$$ language sql
    immutable
    returns null on null input;
comment on function wt_is_sentinel is
  'wt_is_sentinel returns true if string is a sentinel value';

alter domain wt_sentinel
    add constraint wt_sentinel_not_valid
        check(
                wt_is_sentinel(value)
                or
                length(trim(trailing u&'\ffff' from trim(leading u&'\fffe ' from value))) > 0
            );
comment on domain wt_sentinel is
  'A non-empty string with a Unicode prefix of U+FFFE and suffix of U+FFFF to indicate it is a sentinel value';

drop function wt_to_sentinel; -- wt_to_sentinel is not needed, dropping and not re-creating

commit;
