-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  select plan(6);

  -- Verify the function exists and is declared properly
  select has_function('wt_encode_base64_url_safe', array['bytea']);
  select volatility_is('wt_encode_base64_url_safe', 'immutable');
  select is_strict('wt_encode_base64_url_safe');

  -- There are 3 differences between regular base64 and URL safe base64:
  --  1. the '_' character is used in place of '/'
  --  2. the '-' character is used in place of '+'
  --  3. trailing '=' characters used for padding are removed
  --
  --    See https://www.rfc-editor.org/rfc/rfc4648.html#section-5
  --
  -- We only need to test these three changes since wt_encode_base64_url_safe
  -- uses PostgreSQL's native encode function to encode the input into standard
  -- base64.
  --
  -- The input for this test was found at https://commons.apache.org/proper/commons-codec/xref-test/org/apache/commons/codec/binary/Base64Test.html
  --
  -- The regular base64 encoding of the binary data encoded in the hex string '2bf7cc2701fe4397b49ebeed5acc7090'
  -- is 'K/fMJwH+Q5e0nr7tWsxwkA==' which contains the '/', '+', and '='
  -- characters, making it the perfect test case.
  --
  -- Validate this truely is the perfect test case
  select is(encode('\x2bf7cc2701fe4397b49ebeed5acc7090'::bytea, 'base64'), 'K/fMJwH+Q5e0nr7tWsxwkA==');
  -- Now test our function
  select is(wt_encode_base64_url_safe('\x2bf7cc2701fe4397b49ebeed5acc7090'::bytea), 'K_fMJwH-Q5e0nr7tWsxwkA');
  -- Verify the 'returns null on null input' is correct
  select is(wt_encode_base64_url_safe(null), null);

  select * from finish();
rollback;
