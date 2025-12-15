-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

create domain wt_priority as int not null
  constraint priority_must_be_greater_than_zero
    check(value > 0);
comment on domain wt_priority is
  'Represents a priority value which must not be null and must be greater than zero';

-- wt_dns_name defines a type for dns names
create domain wt_dns_name as text not null
    constraint wt_dns_name_too_short
        check (length(trim(value)) > 0)
    constraint wt_dns_name_too_long
        check (length(trim(value)) < 256);
comment on domain wt_dns_name is
  'standard column for dns names';

commit;