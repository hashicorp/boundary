// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

/*
Package perms provides the boundary permissions engine using grants which are
tied to IAM Roles within a Scope.

A really useful page to be aware of when looking at ACLs is
https://hashicorp.atlassian.net/wiki/spaces/ICU/pages/866976600/API+Actions+and+Permissions
speaking of which: TODO: put that chart in public docs.

Anyways, from that page you can see that there are really only a few patterns of
ACLs that are ever allowed:

* type=<resource.type>;actions=<action>
* id=<resource.id>;actions=<action>
* id=<pin>;type=<resource.type>;actions=<action>

and of course a matching scope.

This makes it actually quite simple to perform the ACL checking. Much of ACL
construction is thus synthesizing something reasonable from a set of Grants.
*/
package perms
