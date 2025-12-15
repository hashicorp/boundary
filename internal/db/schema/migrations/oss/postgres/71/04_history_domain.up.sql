-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Encodes binary data into URL safe base64 as specified in RFC 4648 Section 5.
  -- See https://www.rfc-editor.org/rfc/rfc4648.html#section-5
  create function wt_encode_base64_url_safe(bytes bytea) returns text
  as $$
    select rtrim(replace(replace(encode(bytes, 'base64'), '/', '_'), '+', '-'), '=');
  $$ language sql
     immutable
     parallel safe -- all of the functions called are parallel safe
     cost 1        -- all of the functions called are cost 1
     strict;       -- means the function returns null on null input
  comment on function wt_encode_base64_url_safe is
    'Encodes binary data into URL safe base64';

  -- wt_url_safe_id is a domain that constrains the characters of a value to the
  -- unreserved character set defined RFC 3986 Section 2.3. The valid characters are
  -- the ASCII characters in the 'a-z', 'A-Z', or '0-9' ranges plus the four ASCII
  -- characters '~', '-', '.', and '_'.
  --
  -- See https://www.rfc-editor.org/rfc/rfc3986.html#section-2.3
  create domain wt_url_safe_id as text
    constraint wt_url_safe_id_can_only_contain_unreserved_characters
      check (value ~ '^[a-zA-Z0-9\-~\._]+$')
    constraint wt_url_safe_id_must_be_more_than_10_characters
      check (length(trim(value)) > 10);
  comment on domain wt_url_safe_id is
    'An ID that contains only URL safe characters';

  -- wt_url_safe_id is a function that generates a secure random ID of 14
  -- characters suitable for use as a public or private ID. IDs generated with
  -- this function will only contain characters from the unreserved character set
  -- defined in RFC 3986 Section 2.3 making them safe for use in a URL.
  -- See https://www.rfc-editor.org/rfc/rfc3986.html#section-2.3
  create function wt_url_safe_id() returns text
  as $$
    select wt_encode_base64_url_safe(gen_random_bytes(10));
  $$ language sql
     volatile
     parallel safe -- all of the functions called are parallel safe
     cost 1;       -- all of the functions called are cost 1
  comment on function wt_url_safe_id is
    'Returns a random ID of 14 characters containing URL safe characters only';

  create function immutable_table() returns trigger
  as $$
  begin
    raise exception 'immutable table: %', tg_table_name using
      errcode = '23603',
      schema = tg_table_schema,
      table = tg_table_name;
    return null;
  end;
  $$ language plpgsql;
  comment on function immutable_table is
    'immutable_table() is a trigger function that prevents all changes to a table. '
    'It must be added as a trigger to a table before insert, update, and delete events.';

commit;
