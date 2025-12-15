-- Copyright IBM Corp. 2020, 2025
-- SPDX-License-Identifier: BUSL-1.1

begin;
  -- wtt_load populates tables for the given test persona and set of aggregates.
  -- Valid personas are:
  --  * widgets
  --
  -- Valid aggregates:
  --  * iam
  --  * kms
  --  * auth
  --  * hosts
  --  * targets
  --  * credentials
  --  * sessions
  --
  -- Note that some aggregates depend on data from other aggretates, so the order
  -- that they are passed to this function matters.
  create function wtt_load(persona text, variadic aggregates text[]) returns void
  as $$
  declare
    agg text;
    q text;
  begin
    foreach agg in array aggregates
    loop
      q = format('select _wtt_load_%I_%I()', persona, agg);
      execute q;
    end loop;
  end;
  $$ language plpgsql;

commit;
