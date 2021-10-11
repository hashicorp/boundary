begin;
		create table test_three (
      id     tt_public_id primary    key,
      two_id tt_public_id references test_two(id)
    );
commit;
