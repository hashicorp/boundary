-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

-- controller_id tests:
--  validates the wt_controller_id domain

begin;
  select plan(16);

  select has_domain('wt_target_alias');
  
  create table target_alias_testing (
    v wt_target_alias
  );

  prepare empty_insert as insert into target_alias_testing (v) values ('');
  select throws_like(
    'empty_insert',
    '%"wt_alias_too_short"',
    'We should error for empty values'
  );

  prepare valid_inserts as insert into target_alias_testing (v) values 
    ('a'),
    ('A'),
    ('192.168.1.9-9'),
    ('foo'),
    ('a.b.c'),
    ('A.B.C'),
    ('a-b-c'),
    ('a.9-9'),
    ('9things'),
    ('9-things'),
    ('hp--something.test.com'),
    ('test-for-long-name-which-is-almost-over-the-limit-of-characters'),
    ('TEST-FOR-LONG-NAME-WHICH-IS-ALMOST-OVER-THE-LIMIT-OF-CHARACTERS'),
    ('test-for-long-name-which-is-almost-over-the-limit-of-characters.another-label'),
    ('test.test-for-long-name-which-is-almost-over-the-limit-of-characters'),
    ('test-for-long-name-which-is-almost-over-the-limit-of-characters.test-for-long-name-which-is-almost-over-the-limit-of-characters'),
    ('9-things.9-things');
  select lives_ok('valid_inserts');

  prepare label_too_long as insert into target_alias_testing (v) values
  ('test-for-long-name-which-is-almost-over-the-limit-of-charactersX');
    select throws_like(
        'label_too_long',
        '%"wt_target_alias_value_shape"'
    );

  prepare label_too_long_2 as insert into target_alias_testing (v) values
  ('a.test-for-long-name-which-is-almost-over-the-limit-of-charactersX');
    select throws_like(
        'label_too_long_2',
        '%"wt_target_alias_value_shape"'
    );

  prepare label_too_long_3 as insert into target_alias_testing (v) values
  ('test-for-long-name-which-is-almost-over-the-limit-of-charactersX.a');
    select throws_like(
        'label_too_long_3',
        '%"wt_target_alias_value_shape"'
    );

  prepare starting_with_hyphen as insert into target_alias_testing (v) values
  ('-test.com');
    select throws_like(
        'starting_with_hyphen',
        '%"wt_target_alias_value_shape"'
    );

  prepare starting_with_hyphen2 as insert into target_alias_testing (v) values
  ('a.-test');
    select throws_like(
        'starting_with_hyphen2',
        '%"wt_target_alias_value_shape"'
    );

  prepare ending_with_hyphen as insert into target_alias_testing (v) values
  ('test-.com');
    select throws_like(
        'ending_with_hyphen',
        '%"wt_target_alias_value_shape"'
    );

  prepare ending_with_hyphen2 as insert into target_alias_testing (v) values
  ('a.test-');
    select throws_like(
        'ending_with_hyphen2',
        '%"wt_target_alias_value_shape"'
    );

  prepare ending_with_hyphen3 as insert into target_alias_testing (v) values
  ('a.9-');
    select throws_like(
        'ending_with_hyphen3',
        '%"wt_target_alias_value_shape"'
    );

  prepare empty_label as insert into target_alias_testing (v) values
  ('a..com');
    select throws_like(
        'empty_label',
        '%"wt_target_alias_value_shape"'
    );

  prepare empty_label2 as insert into target_alias_testing (v) values
  ('.a.com');
    select throws_like(
        'empty_label2',
        '%"wt_target_alias_value_shape"'
    );

  prepare empty_label3 as insert into target_alias_testing (v) values
  ('a.com.');
    select throws_like(
        'empty_label3',
        '%"wt_target_alias_value_shape"'
    );

  prepare numeric_only_tld as insert into target_alias_testing (v) values
  ('a.123');
    select throws_like(
        'numeric_only_tld',
        '%"wt_target_alias_tld_not_only_numeric"'
    );

  prepare numeric_only_tld2 as insert into target_alias_testing (v) values
  ('a.9');
    select throws_like(
        'numeric_only_tld2',
        '%"wt_target_alias_tld_not_only_numeric"'
    );

  select * from finish();
rollback;
