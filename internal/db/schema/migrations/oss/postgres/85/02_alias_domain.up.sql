-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Constraints wt_alias_too_short, wt_alias_no_suround_spaces, and wt_target_alias_too_long
  -- have been updated in migration 96/01

  -- wt_alias defines a type for alias values
  create domain wt_alias as citext
    constraint wt_alias_too_short
      check (length(trim(value)) > 0)
    constraint wt_alias_no_suround_spaces
      check (trim(value) = value);
  comment on domain wt_alias is
    'standard value column for an alias';

  -- wt_target_alias defines a type for target alias values
  create domain wt_target_alias as wt_alias
    constraint wt_target_alias_too_long
      check (length(trim(value)) < 254)
    -- dns names consists of at least one label joined together by a "."
    -- each label can consist of a-z 0-9 and "-" case insensitive
    -- a label cannot start or end with a "-"
    -- a label can be between 1 and 63 characters long
    -- the final label in the dns name cannot be all numeric
    -- see https://en.wikipedia.org/wiki/Domain_Name_System#Domain_name_syntax,_internationalization
    --
    -- Notes on the regex:
    -- "^(?!-)[a-z0-9-]{0,62}[a-z0-9]" ensures that there is at least one label
    --    * [a-z0-9-]{0,62} allows for the first 0-62 characters to be a-z 0-9 or "-"
    --    * (?!-) is a look ahead to ensure the string does not start with a "-"
    --    * [a-z0-9] at the end ensures that the string ends with a-z 0-9 which
    --       enforces that the label is at least 1 character long which, when
    --       combined with the previous regex, ensures that the label is between
    --       1 and 63 characters long
    -- "(\.((?!-)[a-z0-9-]{0,62}[a-z0-9]))*$" is almost identical to the
    -- previous section and allows for 0 or more additional labels, all of
    -- which must start with a "."
    -- The constraint that the final label is not all numeric is enforced by
    -- the separate constraint wt_target_alias_tld_not_only_numeric 
    constraint wt_target_alias_value_shape
      check (value  ~* '^(?!-)[a-z0-9-]{0,62}[a-z0-9](\.((?!-)[a-z0-9-]{0,62}[a-z0-9]))*$')
    constraint wt_target_alias_tld_not_only_numeric
      check (substring(value from '[^.]*$') !~ '^[0-9]+$');
  comment on domain wt_target_alias is
    'standard value column for a target alias';

commit;
