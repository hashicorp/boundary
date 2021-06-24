begin;

  create function wt_is_sentinel(string text)
    returns bool
  as $$
    select length(trim(trailing u&'\ffff' from trim(leading u&'\fffe ' from string))) > 0 AND starts_with(string, u&'\fffe') AND starts_with(reverse(string), u&'\ffff');
  $$ language sql
     immutable
     returns null on null input;
  comment on function wt_is_sentinel is
    'wt_is_sentinel returns true if string is a sentinel value';

  create domain wt_sentinel as text
    constraint wt_sentinel_not_valid
      check(
        wt_is_sentinel(value)
        or
        length(trim(trailing u&'\ffff' from trim(leading u&'\fffe ' from value))) > 0
      );
  comment on domain wt_sentinel is
  'A non-empty string with a Unicode prefix of U+FFFE and suffix of U+FFFF to indicate it is a sentinel value';

commit;
