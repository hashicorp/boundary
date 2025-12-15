-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- wt_network_address defines a type for a network address.
-- While wt_dns_names does exist, a wt_network_address can be either a dns name
-- or an ip address.
create domain wt_network_address as text
  constraint wt_network_address_too_short
    check (length(trim(value)) > 0)
  constraint wt_network_address_too_long
    check (length(trim(value)) < 256);
comment on domain wt_network_address is
  'standard column for a network address.';


commit;