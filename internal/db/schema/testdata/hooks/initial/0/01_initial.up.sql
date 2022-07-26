begin;
  create domain tt_public_id as text
  check(
    length(trim(value)) > 10
  );
commit;
