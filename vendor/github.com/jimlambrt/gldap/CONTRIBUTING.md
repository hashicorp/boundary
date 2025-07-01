# Contributing to gldap

Thank you for contributing to gldap! Here you can find common questions around
reporting issues and opening pull requests to our project.

When contributing in any way to the gldap project (new issue, PR, etc), please be
aware that our community identifies with many gender pronouns. Please remember
to use nonbinary pronouns (they/them) and gender neutral language ("Hello
folks") when addressing our community. For more reading on our code of conduct,
please see the [Code of Conduct](CODE_OF_CONDUCT.md).

## Issue Reporting

### Reporting Security Related Vulnerabilities

We take gldap's security and our users' trust very seriously. If you believe you
have found a security issue in gldap, please responsibly disclose by contacting
us at <jim.lambert@gmail.com>. Do not open an issue on our GitHub issue tracker if
you believe you've found a security related issue, thank you!

### Bug Fixes

If you believe you found a bug with gldap, please:

1. Build from the latest `main` HEAD commit to attempt to reproduce the issue.
   It's possible we've already fixed the bug, and this is a first good step to
   ensuring that's not the case.
1. Ensure a similar ticket is not already opened by searching our opened issues on GitHub.

Once you've verified the above, feel free to open a bug fix issue template type
from our [issue
selector](https://github.com/hashicorp/jimlambrt/gldap/issues/new/choose) and
we'll do our best to triage it as  quickly as possible.

## Pull Requests

### New Features & Improvements

Before writing a line of code, please ask us about a potential improvement or
feature that you want to write into gldap. We may already be working on it; even
if we aren't, we need to ensure that both the feature and its proposed
implementation is aligned with our road map, vision, and standards for the
project. We're happy to help walk through that via a [feature request
issue](https://github.com/hashicorp/jimlambrt/gldap/issues/new/choose).

You can see a public [road map for gldap](README.md) in the README and we
encourage everyone to look this over to understand at a high level what we're
working on with gldap.

### Submitting a New Pull Request

When submitting a pull request, please ensure:

1. You've followed the above guidelines for contributing to gldap.
2. Make sure you include any [coverage changes](#coverage) with your PR.

Please allow us a couple of days to comment, request changes, or approve your
PR. Thank you for your contribution!

## Testing

To run the entire test suite run this command in the root of the project:

```shell
make test
```

### Running individual tests

If you don't want to run the entire test suite, you can just run a singe test
with go. For example, if you wanted to run the tests
TestDirectory_SimpleBindResponse, you would run:

``` shell
go test -run TestDirectory_SimpleBindResponse 
```

## Coverage

Coverage is published in the repo:
[./coverage/coverage.html](https://raw.githack.com/jimlambrt/gldap/main/coverage/coverage.html#file0)

This report is generate by the cmd:

``` shell
make coverage
```

Please generate a new coverage report and include any changes to the report when
opening a PR.
