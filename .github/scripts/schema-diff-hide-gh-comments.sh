#!/usr/bin/env bash
# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# This script finds all issue comments on a PR that match a specific prefix and
# have been posted by a specific user and minimizes them.

die() {
  # We don't ever return a non-zero status code because GitHub actions exits out
  # of the workflow if any of the commands exit with a non-zero status code. In
  # the case of this script, which is tailored to run in GitHub Actions, the
  # next operation (post a new comment with the new db schema diff) should still
  # run even when this script fails.
  echo "$@"
  exit 0
}

which jq &> /dev/null || die "jq must be installed"
which curl &> /dev/null || die "curl must be installed"

gh_api_url=$1
gh_gql_url=$2
gh_token=$3
gh_repo=$4
gh_pr_number=$5
gh_comment_prefix=$6
gh_user_login=$7

# List all comments for the Pull Request we're working on.
echo "Listing all issue comments for PR #$gh_pr_number"
curl -fsSX GET \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $gh_token" \
  --output response.json \
  $gh_api_url/repos/$gh_repo/issues/$gh_pr_number/comments \
|| die "Failed to list all issue comments for PR #$gh_pr_number"

[[ $(jq 'length' response.json) -gt 0 ]] || die "No comments found for PR #$gh_pr_number, nothing to hide"

# Use jq to find all comments we've posted before (matches against the action
# runner's user login and a partial string match on comment body).
cat response.json \
| jq \
  --arg user_login "$gh_user_login" \
  --arg pfx "$gh_comment_prefix" \
  '.[] |
    select(.user.login == $user_login) |
    select(.body | startswith($pfx)) |
    .node_id
  ' > comment_ids.txt \
|| die 'Failed to parse issue comments response'

[[ $(cat comment_ids.txt | wc -l) -gt 0 ]] || die "No comments matching message prefix and github user id ($gh_user_login) found"

# Build GitHub GraphQL queries for each comment id. Because GitHub doesn't
# return whether a comment is already hidden or not in its comment listing
# endpoint, we have to hide all of them.
while IFS= read -r node_id; do
  echo "mutation { minimizeComment(input: {subjectId: $node_id, classifier: OUTDATED}) { minimizedComment { isMinimized } } }" >> graphql.txt
done <<< "$(cat comment_ids.txt)"

# Parse it through jq to build a valid json object.
while IFS= read -r graphql; do
  jq --null-input -c --arg q "$graphql" '{"query": $q}' >> hide_queries.json \
  || die "Failed to create http minimizeComment query for graphql query $graphql"
done <<< "$(cat graphql.txt)"

# Hide Comments
echo 'Issuing GraphQL calls to GitHub to hide previous schema-diff comments'
while IFS= read -r hide_query; do
  curl -fsSX POST \
    -H "Authorization: Bearer $gh_token" \
    -d "$hide_query" \
    $gh_gql_url \
  || die "Failed to issue request to minimize comment"
done <<< "$(cat hide_queries.json)"
