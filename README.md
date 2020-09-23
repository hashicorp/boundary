# Boundary
![](boundary.png)
----

**Please note**: We take Boundary's security and our users' trust very
seriously. If you believe you have found a security issue in Boundary,
_please responsibly disclose_ by contacting us at
[security@hashicorp.com](mailto:security@hashicorp.com).

----

Boundary is a tool for controlling access to networked resources in the
[SDP](https://en.wikipedia.org/wiki/Software_Defined_Perimeter) model. It is
designed to be straightforward to understand, highly scalable, and resilient.
It can run in clouds, on-prem, secure enclaves and more, and does not require
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

Additionally, Boundary desktop clients are provided that simplify providing
access to request and connect to authorized sessions from desktop machines.

Boundary does _not_ require software to be installed on the endpoint hosts
and services.

## Requirements

Boundary has two external dependencies: a SQL database, and one or more
KMSes.  Both are readily available from cloud vendors, but can be satisfied by
on-premise technologies as well.

* The database contains Boundary's configuration and session information and
  must be accessible by Controller nodes. Values that are secrets (such as
  credentials) are encrypted in the database. Currently, PostgreSQL is
  supported as a database. This need can be satisfied by both hosted and
  self-run instances. For more information on specific requirements and setup,
  see our [Database Guide], however, in most instances all that is needed is a
  database endpoint and appropriate credentials.

* Any cloud KMS or Vault's Transit Secrets Engine can be used to satisfy the
  KMS requirement. Currently, two keys within the KMS are needed: one for
  authenticating other cluster components, which must be accessible by both
  Controllers and Workers; and one for encrypting secret values in the
  database, which need only be accessible to Controllers. These keys can be
  changed over time (so long as the original key remains available for any
  decryption needs), and key derivation is used extensively to avoid key sprawl
  of these high-value keys.

Boundary has a `dev` mode that can be used for testing. In this mode both a
Controller and Worker are started with a single command, and they have the
following properties:

* The Controller will start a PostgreSQL Docker container to use as storage.
  This container will be shut down and removed (if possible) when the
  Controller is (gracefully) shut down.
* The Controller will use an internal KMS with an ephemeral key

## Trying out Boundary
Running Boundary in a more permanent context requires a few more steps, such
as writing some simple configuration files to tell the nodes how to reach their
database and KMS. The steps below, along with the extra information needed
for permanent installations, are detailed in our [Installation Guide].

### Build and Start Boundary in Dev Mode

If you have the following requirements met locally:
- Golang v1.14 or greater
- Docker

You can get up and running with Boundary quickly. Simply run:

  ```make dev```

This will build Boundary. Once complete, run Boundary in `dev` mode:

  ```./$GOPATH/bin/boundary dev```

#### Specify a UI Commitish at Build Time

The default UI build branch is `develop` from [the UI
repo](https://github.com/hashicorp/boundary-ui). A different commitish from
which to build UI assets may be specified via the UI_COMMITISH environment
variable. For example:

  ```UI_COMMITISH=feature-branch make dev```

#### UI Development

It would be impractical to rebuild the binary on every change when actively
developing the UI.  To make UI development more convenient, the binary
supports a _passthrough directory_.  This is an arbitrary local
directory from which UI assets are served.  Note this option is only available
in dev mode.  For example:

  ```BOUNDARY_DEV_PASSTHROUGH_DIRECTORY=/boundary-ui/ui/core/dist ~/go/bin/boundary dev```

### Download and Run from Release Page

Download the latest release of the server binary and appropriate desktop
client(s) from our [releases page]

### Start Boundary

Start the server binary with:

  ```boundary dev```

This will start a Controller service listening on `http://127.0.0.1:9200` for
incoming API requests and a Worker service listening on the same address/port for
incoming session requests. It will also create various default Catalogs and Sets,
and display various bits of information, such as a login name and password that can
be used to log in.

### Configuring Resources

For a simple test of Boundary in `dev` mode you don't generally need to
configure any resources at all! But it's useful to understand what `dev` mode
did for you so you can then take further steps:

In Boundary, a Set is a grouping of resources that share a similarity
suitable for using in configuration; for instance, a User Set combines groups
of users that should have equivalent permissions. Most Sets are automatically
created and managed by Catalogs; for instance, an AWS Catalog can create Host
Sets from EC2 instance, or a Consul Catalog can create Host Sets from Consul
service catalogs. Although you can test out the full functionality of Catalogs
and Sets in `dev` mode, this mode will automatically create some resources for
you suitable for local testing:

* A Host Catalog with a default Host Set containing the local machine
  (`127.0.0.1`) and defining an SSH service on port 22
* A Password User Method with a default User Set containing a user with the
  given login name and associated password. This can be used to log in to the
  web UI and the desktop client.
* A Permissions Set mapping the given User Set to a set of permissions, in this
  case granting access to make connections to resources
* A Credentials Catalog with a default Credential Set that is empty (meaning
  Boundary will require and use the user's credentials when connecting to the
  networked resource; in other words, in this situation it will run in a
  TCP-only mode)

To actually make the connection to the networked resource, a Target must be
defined. Targets group a Host Set, a Credential Set, and a User Set, which,
along with validation against the permissions defined by relevant Permissions
Sets, together allow Boundary to understand what user principals are allowed
to connect where and using what authentication information. A `dev` Boundary
will create a default Target that allows the generated user to make SSH
connections to the local machine on port 22.

You can of course go into Boundary's web UI or use its API to change these
default values, for instance if you instead want to connect to a different host
or need to modify the port to connect to, or want to test out the capabilities
of Boundary to supply the credentials for the session without user
input/knowledge.

### Making the Connection

Next, let's actually make a connection to your local SSH daemon via Boundary:

1. Start the desktop client and point it at the local Boundary `dev` session.
   Log in with the generated login name and password.
2. You can now select the Target that grants access to the local machine and
   hit "Request Session". Doing so will cause Boundary to check whether this
   action is allowed, and if so, send session information back to the client,
   allowing it to start a local authenticated proxy to the Worker. You will be
   shown a CLI command that can be copied and pasted into the CLI to connect to
   the local machine via Boundary.
3. Paste the CLI command into your terminal, or use the given address and port
   in the SSH client of your choice, and connect!
4. When the session has ended, look in the given temporary directory to see
   session information; or navigate to the Sessions page in the web UI to see
   the same information

### Going Further

This example is a simple way to get started but omits several key steps that
could be taken in a production context:

* Using a firewall or other means to restrict the set of hosts allowed to
  connect to a local SSH daemon to only Boundary Worker nodes, thereby making
  Boundary the _only_ means of ingress to a host
* Using credentials specified within Boundary rather than the client's own
  credentials. Because these credentials are not divulged to users, even if a
  user gets around some network-level firewall or other restriction to gain
  direct network access to a host, they will be unable to authenticate.
* Recording the session for later auditing or incident management purposes

`dev` mode by default is operating in a direct proxying mode, where it is
simply passing the network streams along once the session has been authorized.
However, Boundary is built to be flexible and eventually able to understand a
variety of networked protocols, with more capabilities to come in the future.
We have a long roadmap planned out so stay tuned for information about new
features and capabilities!
