-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

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

commit;
