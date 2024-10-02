# Test Case List
This file lists all the test cases for tests under the `pluginhost` package.

## AWS Tests
### Boundary CE
#### Create
  * Static Credentials, no worker filter.
  * Static Credentials, using worker filter.

  * Static credentials (rotated), no worker filter.
  * Static credentials (rotated), using worker filter.

  * AssumeRole credentials, no worker filter.
  * AssumeRole credentials, using worker filter.
  
#### Update
  * Any credentials, no worker filter -> Any credentials, using worker filter

  * Static credentials, no worker filter -> Static (rotated) credentials, no worker filter
  * Static credentials, no worker filter -> AssumeRole credentials, no worker filter.

  * Static (rotated) credentials, no worker filter -> Static credentials, no worker filter.
  * Static (rotated) credentials, no worker filter -> AssumeRole credentials, no worker filter.

  * AssumeRole credentials, no worker filter -> Static credentials, no worker filter.
  * AssumeRole credentials, using worker filter -> Static (rotated) credentials, no worker filter.

#### Delete
  * Static credentials, no worker filter.
  * Static credentials (rotated), no worker filter.
  * AssumeRole credentials, no worker filter.

### Boundary Enterprise
#### Create
  * Static credentials, no worker filter.
  * Static credentials, using worker filter.

  * Static credentials (rotated), no worker filter.
  * Static credentials (rotated), using worker filter.

  * AssumeRole credentials, no worker filter.
  * AssumeRole credentials, using worker filter.

#### Update
  * Static credentials, no worker filter -> Static credentials, using worker filter.
  * Static credentials, no worker filter -> Static (rotated) credentials, no worker filter
  * Static credentials, no worker filter -> Static (rotated) credentials, using worker filter
  * Static credentials, no worker filter -> AssumeRole credentials, no worker filter.
  * Static credentials, no worker filter -> AssumeRole credentials, using worker filter.

  * Static credentials, using worker filter -> Static credentials, no worker filter
  * Static credentials, using worker filter -> Static (rotated) credentials, no worker filter
  * Static credentials, using worker filter -> Static (rotated) credentials, using worker filter
  * Static credentials, using worker filter -> AssumeRole credentials, no worker filter.
  * Static credentials, using worker filter -> AssumeRole credentials, using worker filter.

  * Static (rotated) credentials, no worker filter -> Static (rotated) credentials, using worker filter
  * Static (rotated) credentials, no worker filter -> Static credentials, no worker filter.
  * Static (rotated) credentials, no worker filter -> Static credentials, using worker filter.
  * Static (rotated) credentials, no worker filter -> AssumeRole credentials, no worker filter.
  * Static (rotated) credentials, no worker filter -> AssumeRole credentials, using worker filter.

  * Static (rotated) credentials, using worker filter  -> Static (rotated) credentials, no worker filter 
  * Static (rotated) credentials, using worker filter -> Static credentials, no worker filter.
  * Static (rotated) credentials, using worker filter -> Static credentials, using worker filter.
  * Static (rotated) credentials, using worker filter -> AssumeRole credentials, no worker filter.
  * Static (rotated) credentials, using worker filter -> AssumeRole credentials, using worker filter.

  * AssumeRole credentials, no worker filter -> AssumeRole credentials, using worker filter.
  * AssumeRole credentials, no worker filter -> Static credentials, no worker filter.
  * AssumeRole credentials, no worker filter -> Static credentials, using worker filter.
  * AssumeRole credentials, no worker filter -> Static (rotated) credentials, no worker filter.
  * AssumeRole credentials, no worker filter -> Static (rotated) credentials, using worker filter.

  * AssumeRole credentials, using worker filter -> AssumeRole credentials, no worker filter.
  * AssumeRole credentials, using worker filter -> Static credentials, no worker filter.
  * AssumeRole credentials, using worker filter -> Static credentials, using worker filter.
  * AssumeRole credentials, using worker filter -> Static (rotated) credentials, no worker filter.
  * AssumeRole credentials, using worker filter -> Static (rotated) credentials, using worker filter.

#### Delete
  * Static credentials, no worker filter.
  * Static credentials, using worker filter.

  * Static credentials (rotated), no worker filter.
  * Static credentials (rotated), using worker filter.

  * AssumeRole credentials, no worker filter.
  * AssumeRole credentials, using worker filter.
