## [gldap.testdirectory](testdirectory/)
[![Go
Reference](https://pkg.go.dev/badge/github.com/jimlambrt/gldap/testdirectory.svg)](https://pkg.go.dev/github.com/jimlambrt/gldap/testdirectory)

The `testdirectory` package provides an in-memory test LDAP service with support
for capabilities which make writing tests that depend on an LDAP service much
easier. 

`testdirectory` is also a great working example of how you can use `gldap` to build a custom
ldap server to meet your specific needs.


Example:

```go

// this example demonstrates how can start a test directory for your 
// unit tests which will automatically stop when the test is complete. 
func TestDirectory_SimpleBindResponse(t *testing.T) {

	// start a test directory running ldaps on an available free port (defaults)
	// that allows anon binds (a default override)
	td := testdirectory.Start(t,
		testdirectory.WithDefaults(&testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	// create some test new user entries (using defaults for ou, password, etc)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"})
	// set the test directories user entries
	td.SetUsers(users...)
}
```