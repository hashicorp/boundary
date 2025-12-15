-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

-- wt_email defines a type for email which must be less than 320 chars and only
-- contain lower case values.  The type is defined to allow nulls and not be
-- unique, which can be overriden as needed when used in tables.
create domain wt_email as text
    constraint wt_email_too_short
        check (length(trim(value)) > 0)
    constraint wt_email_too_long
        check (length(trim(value)) < 320);
comment on domain wt_email is
  'standard column for email addresses';

-- wt_full_name defines a type for a person's full name which must be less than
-- 512 chars.  The type is defined to allow nulls and not be unique, which can
-- be overriden as needed when used in tables. 
create domain wt_full_name text 
    constraint wt_full_name_too_short
        check (length(trim(value)) > 0)
    constraint wt_full_name_too_long
        check(length(trim(value)) <= 512); -- gotta pick some upper limit.
comment on domain wt_full_name is
  'standard column for the full name of a person';

-- wt_url defines a type for URLs which must be longer that 3 chars and
-- less than 4k chars.  It's defined to allow nulls, which can be overridden as
-- needed when used in tables.
create domain wt_url as text
    constraint wt_url_too_short
        check (length(trim(value)) > 3)
    constraint wt_url_too_long
        check (length(trim(value)) < 4000)
    constraint wt_url_invalid_protocol
        check (value ~ 'https?:\/\/*');
comment on domain wt_url is
  'standard column for URLs';

-- wt_name defines a type for resource names that must be less than 128 chars.
--  It's defined to allow nulls.
create domain wt_name as text
    constraint wt_name_too_short
        check (length(trim(value)) > 0)
    constraint wt_name_too_long
        check (length(trim(value)) < 128);
comment on domain wt_name is
  'standard column for resource names';

-- wt_description defines a type for resource descriptions that must be less
-- than 1024 chars. It's defined to allow nulls.
create domain wt_description as text
    constraint wt_description_too_short
        check (length(trim(value)) > 0)
    constraint wt_description_too_long
        check (length(trim(value)) < 1024);
comment on domain wt_description is
  'standard column for resource descriptions';

commit;
