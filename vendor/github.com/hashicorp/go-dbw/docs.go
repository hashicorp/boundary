// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

/*
Package dbw is a database wrapper that supports connecting and using any database with a
gorm driver.  It's intent is to completely encapsulate an application's access
to it's database with the exception of migrations.

dbw is intentionally not an ORM and it removes typical ORM abstractions like
"advanced query building", associations and migrations.

This is not to say you can't easily use dbw for complicated queries, it's just
that dbw doesn't try to reinvent sql by providing some sort of pattern for
building them with functions. Of course, dbw also provides lookup/search
functions when you simply need to read resources from the database.

dbw strives to make CRUD for database resources fairly trivial.  Even supporting
"on conflict" for its create function.  dbw also allows you to opt out of its
CRUD functions and use exec, query and scan rows directly.  You may want to
carefully weigh when it's appropriate to use exec and query directly, since
it's likely that each time you use them you're leaking a bit of your
database schema into your application's domain.

For more information see README.md
*/
package dbw
