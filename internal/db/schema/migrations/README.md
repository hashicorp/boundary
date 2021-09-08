# migrations package
This package handles the generation of the database schema in a format that can
be compiled into the boundary binary.

## Organization

* `./generate`: contains the makefile, code, and templates needed to generate the schema info.
* `./postgres`: contains the versioned schema folders.  The contents of these folders, except
 for `dev` should not be modified.
 
## Usage
To regenerate the schema information into the format the boundary binary uses run
`make migrations` or `make gen` to recreate all generated code.

The content of the folders under `./postgres` are compiled into the
boundary binary and when the `boundary database init` or `boundary database migrate`
commands are executed they are applied in order of their version.

The `./postgres/dev` directory contains schema files that are under development and
are not included in a release yet and so it is the only directory where additions and
modifications are allowed.  When a boundary binary is built when this directory is not 
empty a special flag is required to run the `boundary database init` command to indicate
the user is aware that this is a development release and running this command can
result in a completely broken schema and dataloss.

When a new release is made the contents of the `dev` directory are moved into a new
versioned directory.