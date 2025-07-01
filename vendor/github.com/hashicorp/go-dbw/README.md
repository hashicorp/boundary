# dbw package
[![Go Reference](https://pkg.go.dev/badge/github.com/hashicorp/go-dbw.svg)](https://pkg.go.dev/github.com/hashicorp/go-dbw)
[![Go Report Card](https://goreportcard.com/badge/github.com/hashicorp/go-dbw)](https://goreportcard.com/report/github.com/hashicorp/go-dbw)
[![Go Coverage](https://raw.githack.com/hashicorp/go-dbw/main/coverage/coverage.svg)](https://raw.githack.com/hashicorp/go-dbw/main/coverage/coverage.html)

[dbw](https://pkg.go.dev/github.com/hashicorp/go-dbw) is a database wrapper that 
supports connecting and using any database with a
[GORM](https://github.com/go-gorm/gorm) driver.   

[dbw](https://pkg.go.dev/github.com/hashicorp/go-dbw) is intended to completely
encapsulate an application's access to its database with the exception of
migrations. [dbw](https://pkg.go.dev/github.com/hashicorp/go-dbw) is
intentionally not an ORM and it removes typical ORM abstractions like "advanced
query building", associations and migrations.    

Of course you can use [dbw](https://pkg.go.dev/github.com/hashicorp/go-dbw) for
complicated queries, it's just that
[dbw](https://pkg.go.dev/github.com/hashicorp/go-dbw) doesn't try to reinvent
SQL by providing some sort of pattern for building them with functions. Of
course, [dbw](https://pkg.go.dev/github.com/hashicorp/go-dbw) also provides
lookup/search functions when you simply need to read resources from the
database. 

[dbw](https://pkg.go.dev/github.com/hashicorp/go-dbw) strives to make CRUD for
database resources fairly trivial for common use cases. It also supports an
[WithOnConflict(...)](https://pkg.go.dev/github.com/hashicorp/go-dbw#WithOnConflict)
option for its
[RW.Create(...)](https://pkg.go.dev/github.com/hashicorp/go-dbw#RW.Create) 
function for complex scenarios. [dbw](https://pkg.go.dev/github.com/hashicorp/go-dbw) also allows you to opt out of its CRUD
functions and use exec, query and scan rows directly. You may want to carefully
weigh when it's appropriate to use exec and query directly, since it's likely that
each time you use them you're leaking a bit of your database layer schema into
your application's domain.  

* [Usage highlights](./docs/README_USAGE.md)
* [Declaring Models](./docs/README_MODELS.md)
* [Connecting to a Database](./docs/README_OPEN.md)
* [Options](./docs/README_OPTIONS.md)
* [NonCreatable and NonUpdatable](./docs/README_INITFIELDS.md)
* [Readers and Writers](./docs/README_RW.md)
* [Create](./docs/README_CREATE.md)
* [Read](./docs/README_READ.md)
* [Update](./docs/README_UPDATE.md)
* [Delete](./docs/README_DELETE.md)
* [Queries](./docs/README_QUERY.md)
* [Transactions](./docs/README_TX.md)
* [Hooks](./docs/README_HOOKS.md)
* [Optimistic locking for write operations](./docs/README_LOCKS.md)
* [Debug output](./docs/README_DEBUG.md)
