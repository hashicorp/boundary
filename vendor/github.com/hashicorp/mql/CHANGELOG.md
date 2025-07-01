# mql CHANGELOG

Canonical reference for changes, improvements, and bugfixes for mql.

## Next

## 0.1.5

* fix (parser): fix issue #42 related to WS before rparen in [[PR](https://github.com/hashicorp/mql/pull/47)]
* feat: add support for table column mapping by @dlclark in [[PR](https://github.com/hashicorp/mql/pull/45)]
* feat: add support for table column name from struct tags @terminalfi in [[PR](https://github.com/hashicorp/mql/pull/50)]
* chore: update deps by @jimlambrt in [[PR](https://github.com/hashicorp/mql/pull/54)]

## 0.1.4 (2024/05/14)

* feat: supports configuring multiple converters by @qeesung in [[PR](https://github.com/hashicorp/mql/pull/38)]
* chore: update deps by @jimlambrt in [[PR](https://github.com/hashicorp/mql/pull/39)]
* chore (tests/postgres): update deps by @jimlambrt in [[PR](https://github.com/hashicorp/mql/pull/40)]

## 0.1.3 (2023/12/19)

* chore(deps): bump golang.org/x/crypto from 0.7.0 to 0.17.0 in /tests/postgres ([PR](https://github.com/hashicorp/mql/pull/33))
* fix (parse): queries with multiple columns need to properly handle right-side
  logic expressions when they are complete expressions (having both a left and
  right side). ([PR](https://github.com/hashicorp/mql/pull/34))
* chore: add github action to check diffs on generated bits ([PR](https://github.com/hashicorp/mql/pull/32))
* chore: add race checker to "go test" in github action ([PR](https://github.com/hashicorp/mql/pull/31))
* chore: add govulncheck to github actions ([PR](https://github.com/hashicorp/mql/pull/30))
* update go matrix in CI: remove 1.18 and add 1.21 ([PR](https://github.com/hashicorp/mql/pull/30))

## 0.1.2 (2023/09/18)

* fix: remove "like" from sql keywords checked in fuzzing ([PR](https://github.com/hashicorp/mql/pull/26))
* feat: add support for backtick and single-quote string delimiters ([PR](https://github.com/hashicorp/mql/pull/25))
* feat: require string tokens used as comparison values to be delimited ([PR](https://github.com/hashicorp/mql/pull/23))
* chore: automate some coverage reporting bits ([PR](https://github.com/hashicorp/mql/pull/12))
* tests: add fuzz test for mql.Parse(...)([PR](https://github.com/hashicorp/mql/pull/11))

## 0.1.1 (2023/08/16)

It was a fast-follower patch release, but was needed to support developers that
use the [database/sql](https://pkg.go.dev/database/sql) package.

* tests: add postgres integration tests ([PR](https://github.com/hashicorp/mql/pull/8)).
* feat: add WithPgPlaceholder() option
  ([PR](https://github.com/hashicorp/mql/pull/7)). This PR was critical to
  support folks who use the
  [database/sql](https://pkg.go.dev/database/sql) package.

## 0.1.0 (2023/08/15)

v0.1.0 is the first release.  As a result there are no changes, improvements, or bugfixes from past versions.
