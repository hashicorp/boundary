# Boundary
![](boundary.png)

----

**Please note**: We take Boundary's security and our users' trust very
seriously. If you believe you have found a security issue in Boundary,
_please responsibly disclose_ by contacting us at
[security@hashicorp.com](mailto:security@hashicorp.com).

----

Boundary provides simple and secure access to hosts and services.

Traditional approaches like SSH bastion hosts or VPNs require distributing and managing 
credentials, configuring network controls like firewalls, and exposing the private 
network. Boundary provides a secure way to access hosts and critical systems without 
having to manage credentials or expose your network, and is entirely open source.

Boundary is designed to be straightforward to understand, highly scalable, and 
resilient. It can run in clouds, on-prem, secure enclaves and more, and does not require
an agent to be installed on every end host.

Unlike firewalls, Boundary performs per-access authentication and
authorization checks, allowing for much higher level mappings of users to
services or hosts than at network layers. Although complementary to secrets
managers (like HashiCorp's own [Vault](https://www.vaultproject.io/)),
Boundary fills a different niche, allowing the credential that is eventually
used to be hidden entirely from the user.

Getting Started
-------------------------------

Boundary consists of two server components: Controllers, which serve the API
and coordinate session requests; and Workers, which perform the actual session
handling. A normal Boundary installation will consist of one or more
Controllers paired with one or more Workers. A single Boundary binary can act
in either of these two modes.

Additionally, Boundary provides a client that provides access to request and
connect to authorized sessions.

Boundary does _not_ require software to be installed on the endpoint hosts
and services.

## Requirements

Boundary has two external dependencies: a SQL database, and one or more
KMSes.  Both are readily available from cloud vendors, but can be satisfied by
on-premises technologies as well.

* The database contains Boundary's configuration and session information and
  must be accessible by Controller nodes. Values that are secrets (such as
  credentials) are encrypted in the database. Currently, PostgreSQL is supported
  as a database and has been tested with Postgres 12 and above. Boundary uses
  only common extensions and both hosted and self-run instances are supported.
  In most instances all that is needed is a database endpoint and appropriate
  credentials.

* Any cloud KMS or Vault's Transit Secrets Engine can be used to satisfy the KMS
  requirement. Currently, two keys within the KMS are required: one for
  authenticating other cluster components, which must be accessible by both
  Controllers and Workers; and one for encrypting secret values in the database,
  which need only be accessible to Controllers. These keys can be changed over
  time (so long as the original key remains available for any decryption needs),
  and key derivation is used extensively to avoid key sprawl of these high-value
  keys. If available, other keys can be used for other purposes, such as
  recovery functionality and encryption of sensitive values in Boundary's config
  file.

Boundary has a `dev` mode that can be used for testing. In this mode both a
Controller and Worker are started with a single command, and they have the
following properties:

* The Controller will start a PostgreSQL Docker container to use as storage.
  This container will be shut down and removed (if possible) when the
  Controller is (gracefully) shut down.
* The Controller will use an internal KMS with ephemeral keys

## Trying out Boundary

Running Boundary in a more permanent context requires a few more steps, such
as writing some simple configuration files to tell the nodes how to reach their
database and KMS. The steps below, along with the extra information needed
for permanent installations, are detailed in our [Installation Guide](https://www.boundaryproject.io/docs/installing).

### Build and Start Boundary in Dev Mode

**NOTE**: Do _not_ use the `main` branch except for dev or test cases. Boundary 0.10 introduced release branches which should be safe to track, however, migrations in `main` may be renumbered if needed. The Boundary team will not be able to provide assistance if running `main` over the long term results in migration breakages.

If you have the following requirements met locally:
- Golang v1.19 or greater
- Docker
- Either the [Boundary UI Dependencies](https://github.com/hashicorp/boundary-ui#prerequisites)
  for locally building the ui assets
  or [gh cli](https://cli.github.com) for downloading pre-built ui assets.

You can get up and running with Boundary quickly. Simply run:

  ```make install```

This will build Boundary. (The first time this is run it will fetch and compile
UI assets; which will take a few extra minutes.) Once complete, run Boundary in
`dev` mode:

  ```$GOPATH/bin/boundary dev```

Please note that development may require other tools; to install the set of
tools at the versions used by the Boundary team, run:

  ```make tools```

Without doing so, you may encounter errors while running `make install`. It is important
to also note that using `make tools` will install various tools used for Boundary
development to the normal Go binary directory; this may overwrite or take precedence
over tools that might already be installed on the system.

#### Specify a UI Commitish at Build Time

By default the UI will be built from a preselected commit ID from [the UI
repo](https://github.com/hashicorp/boundary-ui). A different commitish from
which to build UI assets may be specified via the UI_COMMITISH environment
variable. For example:

  ```UI_COMMITISH=feature-branch make build-ui```

will update your local UI assets.

#### UI Build Troubleshooting

UI assets are built within a Docker container.  If you encounter issues with
this build step, trying increasing memory and swap available to Docker.

#### UI Development

It would be impractical to rebuild the binary on every change when actively
developing the UI. To make UI development more convenient, the binary supports a
_passthrough directory_. This is an arbitrary local directory from which UI
assets are served. Note this option is only available in dev mode. For example:

  ```BOUNDARY_DEV_UI_PASSTHROUGH_DIR=/boundary-ui/ui/admin/dist ~/go/bin/boundary dev```

### Download and Run from Release Page

Download the latest release of the server binary and appropriate desktop
client(s) from our [releases page](https://releases.hashicorp.com/boundary/)

### Start Boundary

Start the server binary with:

  ```boundary dev```

This will start a Controller service listening on `http://127.0.0.1:9200` for
incoming API requests and a Worker service listening on `http://127.0.0.1:9202`
for incoming session requests. It will also create various default resources and
display various useful pieces of information, such as a login name and password
that can be used to authenticate.

### Configuring Resources

For a simple test of Boundary in `dev` mode you don't generally need to
configure any resources at all! But it's useful to understand what `dev` mode
did for you so you can then take further steps. By default, `dev` mode will
create:

* The `global` Scope for initial authentication, containing a Password-type
  Auth Method, along with an Account for login.
* An organization Scope under `global`, and a project Scope inside the
  organization.
* A Host Catalog with a default Host Set, which itself contains a Host with the
  address of the local machine (`127.0.0.1`)
* A Target mapping the Host Set to a set of connection parameters, with a
  default port of `22` (e.g. SSH)

You can of course go into Boundary's web UI or use its API to change these
default values, for instance if you want to connect to a different host or need
to modify the port on which to to connect.

### Making the Connection

Next, let's actually make a connection to your local SSH daemon via Boundary:

1. Authenticate to Boundary; using default `dev` values, this would be `boundary
   authenticate password -auth-method-id ampw_1234567890 -login-name admin
   -password password`. (Note that if you do not include the `password` flag you
   will be prompted for it.)
2. Run `boundary connect ssh -target-id ttcp_1234567890`. If you want to adjust
   the username, pass `-username <name>` to the command.

A lot more is possible with Boundary, even at this early stage. Check out the
possibilities for target configuration to test out limiting (or increasing) the
number of connections per session or setting a maximum time limit; try canceling
an active session from the sessions page or via `boundary sessions`, make your
own commands with `boundary connect -exec`, and so on.

### Going Further

This example is a simple way to get started but omits several key steps that
could be taken in a production context:

* Using a firewall or other means to restrict the set of hosts allowed to
  connect to a local service to only Boundary Worker nodes, thereby making
  Boundary the _only_ means of ingress to a host
* Using the Boundary Terraform provider to easily integrate Boundary with your
  existing code-based infrastructure
* Pointing a BI tool (PowerBI, Tableau, etc.) at Boundary's session warehouse to
  generate insights and look for anomalies with respect to session access

There are many, many more things that Boundary will do in the future in terms of
integrations, features, and more. We have a long roadmap planned out, so stay
tuned for information about new features and capabilities!

## Contributing

Thank you for your interest in contributing! Please refer to
[CONTRIBUTING.md](https://github.com/hashicorp/boundary/blob/main/CONTRIBUTING.md) for guidance.
