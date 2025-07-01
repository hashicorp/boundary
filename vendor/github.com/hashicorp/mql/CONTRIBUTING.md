# Contributing to MQL

Thank you for contributing to MQL! Here you can find common questions around
reporting issues and opening pull requests to our project.

## Issue Reporting

### Reporting Security Related Vulnerabilities

We take MQL's security and our users' trust very seriously. If you believe you
have found a security issue in MQL, please responsibly disclose by contacting us
at security@hashicorp.com. Do not open an issue on our GitHub issue tracker if
you believe you've found a security related issue, thank you!

### Bug Fixes

If you believe you found a bug with MQL, please:

1. Build from the latest `main` HEAD commit to attempt to reproduce the issue.
   It's possible we've already fixed the bug, and this is a first good step to
   ensuring that's not the case.
1. Ensure a similar ticket is not already opened by searching our opened issues
   on GitHub.

Once you've verified the above, feel free to open a bug fix issue template type
from our [issue selector](https://github.com/hashicorp/mql/issues/new/choose)
and we'll do our best to triage it as quickly as possible.

## Pull Requests

### New Features & Improvements

Before writing a line of code, please ask us about a potential improvement or
feature that you want to write into MQL. We may already be working on it;
even if we aren't, we need to ensure that both the feature and its proposed
implementation is aligned with our road map, vision, and standards for the
project. We're happy to help walk through that via a [feature request
issue](https://github.com/hashicorp/mql/issues/new/choose).

### Submitting a New Pull Request

When submitting a pull request, please ensure:

1. You've added a changelog line clearly describing the new addition under the
   correct changelog sub-section.
1. You've followed the above guidelines for contributing to MQL.

Once you open your PR, please allow us a couple of days to comment, request
changes, or approve your PR.  Once a PR is created, please do not rebase your PR
branch, since rebasing would make it more difficult to review requested PR
changes. Accepted PR commits will be squashed into a single commit when
they are merged.

Thank you for your contribution!

## Changelog

The changelog is updated by PR contributors. Each contribution to MQL should
include a changelog update at the contributor or reviewer discretion. The
changelog should be updated when the contribution is large enough to warrant it
being called out in the larger release cycle. Enhancements, bug fixes, and other
contributions that practitioners might want to be aware of should exist in the
changelog. 

When contributing to the changelog, follow existing patterns for referencing
PR's, issues or other ancillary context.

The changelog is broken down into sections:

### Next

The current release cycle. New contributions slated for the next release should
go under this heading. If the contribution is being backported, the inclusion of
the feature in the appropriate release during the backport process is handled
on an as-needed basis.

### New and Improved

Any enhancements, new features, etc fall into this section. 

### Bug Fixes

Any bug fixes fall into this section.

****
