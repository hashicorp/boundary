# Contributing to Boundary

Thank you for contributing to Boundary! Here you can find common questions around reporting issues and opening
pull requests to our project.

When contributing in any way to the Boundary project (new issue, PR, etc), please be aware that our team identifies with many gender pronouns. Please remember to use nonbinary pronouns (they/them) and gender neutral language ("Hello folks") when addressing our team. For more reading on our code of conduct, please see the [HashiCorp community guidelines](https://www.hashicorp.com/community-guidelines). 

## Issue Reporting
### Reporting Security Related Vulnerabilities

We take Boundary's security and our users' trust very seriously. If you believe you have found a security issue 
in Boundary, please responsibly disclose by contacting us at security@hashicorp.com. Do not open an issue on 
our GitHub issue tracker if you believe you've found a security related issue, thank you!

### Bug Fixes

If you believe you found a bug with Boundary, please:

1. Build from the latest `main` HEAD commit to attempt to reproduce the issue. It's possible we've already fixed
the bug, and this is a first good step to ensuring that's not the case.
1. Take a look at the [Boundary Discuss](https://discuss.hashicorp.com/c/boundary/50) to see if other folks have had
similar issues.
1. Ensure a similar ticket is not already opened by searching our opened issues on GitHub.


Once you've verified the above, feel free to open a bug fix issue template type from our [issue selector](https://github.com/hashicorp/boundary/issues/new/choose)
and we'll do our best to triage it as quickly as possible. 

## Pull Requests

### New Features & Improvements

Before writing a line of code, please ask us about a potential improvement or feature that you want to write into Boundary. We may already be working on it; even if we aren't, we need to ensure that both the feature and its proposed implementation is aligned with our road map, vision, and standards for the project. We're happy to help walk through that via a [feature request issue](https://github.com/hashicorp/boundary/issues/new/choose).

You can see a public [road map for Boundary](https://github.com/hashicorp/boundary/issues/new/choose) on our docs site and we encourage
everyone to look this over to understand at a high level what we're working on with Boundary.

### Submitting a New Pull Request

When submitting a pull request, please ensure:

1. You've added a changelog line clearly describing the new addition under the correct changelog sub-section.
1. You've followed the above guidelines for contributing to Boundary.

Once you open your PR, our auto-labeling will add labels to help us triage and prioritize your contribution. Please
allow us a couple of days to comment, request changes, or approve your PR. Thank you for your contribution!

## Changelog

The changelog is updated by PR contributors. Each contribution to Boundary should include a changelog update at the contributor or reviewer discretion. 
The changelog should be updated when the contribution is large enough to warrant it being called out in the larger release cycle. Enhancements, bug fixes,
and other contributions that practitioners might want to be aware of should exist in the changelog. 

When contributing to the changelog, follow existing patterns for referencing PR's, issues or other ancillary context.

The changelog is broken down into sections:

### vNext

The current release cycle. New contributions slated for the next release should go under this heading. If the contribution is being backported,
the inclusion of the feature in the appropriate release during the backport process is handled on an as-needed basis. 

### New and Improved

Any enhancements, new features, etc fall into this section. 

### Bug Fixes

Any bug fixes fall into this section.

## Testing

To run the entire test suite run this command in the root of the project:

```
$ make test
```

Before running any test please ensure that Docker is started. Boundary uses a Docker container to initiate a database for testing.
If a test is interrupted check to make certain that all Docker containers have been properly destroyed. 

### Running individual tests

If you don't want to run the entire test suite, you can just run a singe test
with go. For example, if you wanted to run the tests TestAuthTokenAuthenticator, you would
run:

```
$ go test -run TestAuthTokenAuthenticator -v ./internal/auth
```
