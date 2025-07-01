# gldap
[![Go Reference](https://pkg.go.dev/badge/github.com/jimlambrt/gldap/gldap.svg)](https://pkg.go.dev/github.com/jimlambrt/gldap)
[![Go Coverage](https://raw.githack.com/jimlambrt/gldap/main/coverage/coverage.svg)](https://raw.githack.com/jimlambrt/gldap/main/coverage/coverage.html)
[![Go Report Card](https://goreportcard.com/badge/github.com/jimlambrt/gldap)](https://goreportcard.com/report/github.com/jimlambrt/gldap)

<hr>

`gldap` is a framework for building LDAP services.  Among other things, it defines abstractions for:

* `Server`: supports both LDAP and LDAPS (TLS) protocols as well as the StartTLS
  requests. 
* `Request`: represents an LDAP request (bind, search, extended, etc) along with
  the inbound request message. 
* `ResponseWriter`: allows you to compose request responses.
* `Mux`: an ldap request multiplexer. It matches the inbound request against a
  list of registered route handlers. 
* `HandlerFunc`: handlers provided to the Mux which serve individual ldap requests.

<hr>

Example:

```go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jimlambrt/gldap"
)

func main() {
	// create a new server
	s, err := gldap.NewServer()
	if err != nil {
		log.Fatalf("unable to create server: %s", err.Error())
	}

	// create a router and add a bind handler
	r, err := gldap.NewMux()
	if err != nil {
		log.Fatalf("unable to create router: %s", err.Error())
	}
	r.Bind(bindHandler)
	r.Search(searchHandler)
	s.Router(r)
	go s.Run(":10389") // listen on port 10389

	// stop server gracefully when ctrl-c, sigint or sigterm occurs
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	select {
	case <-ctx.Done():
		log.Printf("\nstopping directory")
		s.Stop()
	}
}

func bindHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(
		gldap.WithResponseCode(gldap.ResultInvalidCredentials),
	)
	defer func() {
		w.Write(resp)
	}()

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		log.Printf("not a simple bind message: %s", err)
		return
	}

	if m.UserName == "alice" {
		resp.SetResultCode(gldap.ResultSuccess)
		log.Println("bind success")
		return
	}

func searchHandler(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewSearchDoneResponse()
	defer func() {
		w.Write(resp)
	}()
	m, err := r.GetSearchMessage()
	if err != nil {
		log.Printf("not a search message: %s", err)
		return
	}
	log.Printf("search base dn: %s", m.BaseDN)
	log.Printf("search scope: %d", m.Scope)
	log.Printf("search filter: %s", m.Filter)

	if strings.Contains(m.Filter, "uid=alice") || m.BaseDN == "uid=alice,ou=people,cn=example,dc=org" {
		entry := r.NewSearchResponseEntry(
			"uid=alice,ou=people,cn=example,dc=org",
			gldap.WithAttributes(map[string][]string{
				"objectclass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
				"uid":         {"alice"},
				"cn":          {"alice eve smith"},
				"givenname":   {"alice"},
				"sn":          {"smith"},
				"ou":          {"people"},
				"description": {"friend of Rivest, Shamir and Adleman"},
				"password":    {"{SSHA}U3waGJVC7MgXYc0YQe7xv7sSePuTP8zN"},
			}),
		)
		entry.AddAttribute("email", []string{"alice@example.org"})
		w.Write(entry)
		resp.SetResultCode(gldap.ResultSuccess)
	}
	if m.BaseDN == "ou=people,cn=example,dc=org" {
		entry := r.NewSearchResponseEntry(
			"ou=people,cn=example,dc=org",
			gldap.WithAttributes(map[string][]string{
				"objectclass": {"organizationalUnit"},
				"ou":          {"people"},
			}),
		)
		w.Write(entry)
		resp.SetResultCode(gldap.ResultSuccess)
	}
	return
}
```
<hr>

## Road map

### Currently supported features:

* `ldap`, `ldaps` and `mTLS` connections
* StartTLS Requests
* Bind Requests
  * Simple Auth (user/pass) 
* Search Requests
* Modify Requests
* Add Requests
* Delete Requests
* Unbind Requests

### Future features
At this point, we may wait until issues are opened before planning new features
given that all the basic LDAP operations are supported. 

<hr>

## [gldap.testdirectory](testdirectory/README.md)
[![Go
Reference](https://pkg.go.dev/badge/github.com/jimlambrt/gldap/testdirectory.svg)](https://pkg.go.dev/github.com/jimlambrt/gldap/testdirectory) 

The `testdirectory` package built using `gldap` which provides an in-memory test
LDAP service with capabilities which make writing tests that depend on an LDAP
service much easier.  

`testdirectory` is also a great working example of how you can use `gldap` to build a custom
ldap server to meet your specific needs.

Example:

```go
// this testdirectory example demonstrates how can start a test directory for 
// your unit tests which will automatically stop when the test is complete. 
func TestExample(t *testing.T) {

	// start a test directory running ldaps on an available free port (defaults)
	// that allows anon binds (a default override)
	td := testdirectory.Start(t,
		testdirectory.WithDefaults(&testdirectory.Defaults{AllowAnonymousBind: true}),
	)
	// create some test new user entries (using defaults for ou, password, etc)
	users := testdirectory.NewUsers(t, []string{"alice", "bob"})
	// set the test directories user entries
	td.SetUsers(users...)

	// INSERT your tests here....
}
```