// Copyright (c) Jim Lambert
// SPDX-License-Identifier: MIT

package testdirectory

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
)

const (
	// DefaultUserAttr is the "username" attribute of the entry's DN and is
	// typically either the cn in ActiveDirectory or uid in openLDAP  (default:
	// cn)
	DefaultUserAttr = "cn"

	// DefaultGroupAttr for the ClientConfig.GroupAttr
	DefaultGroupAttr = "cn"

	// DefaultUserDN defines a default base distinguished name to use when
	// searching for users for the Directory
	DefaultUserDN = "ou=people,dc=example,dc=org"

	// DefaultGroupDN defines a default base distinguished name to use when
	// searching for groups for the Directory
	DefaultGroupDN = "ou=groups,dc=example,dc=org"
)

// Directory is a local ldap directory that supports test ldap capabilities
// which makes writing tests much easier.
//
// It's important to remember that the Directory is stateful (see any of its
// receiver functions that begin with Set*)
//
// Once you started a Directory with Start(...), the following
// test ldap operations are supported:
//
//   - Bind
//   - StartTLS
//   - Search
//   - Modify
//   - Add
//
// Making requests to the Directory is facilitated by:
//   - Directory.Conn()		returns a *ldap.Conn connected to the Directory (honors WithMTLS options from start)
//   - Directory.Cert() 		returns the pem-encoded CA certificate used by the directory.
//   - Directory.Port() 		returns the port the directory is listening on.
//   - Directory.ClientCert() 	returns a client cert for mtls
//   - Directory.ClientKey() 	returns a client private key for mtls
type Directory struct {
	t      TestingT
	s      *gldap.Server
	logger hclog.Logger
	port   int
	host   string
	useTLS bool
	client *tls.Config
	server *tls.Config

	mu                 sync.Mutex
	users              []*gldap.Entry
	groups             []*gldap.Entry
	tokenGroups        map[string][]*gldap.Entry // string == SID
	allowAnonymousBind bool
	controls           []gldap.Control

	// userDN is the base distinguished name to use when searching for users
	userDN string
	// groupDN is the base distinguished name to use when searching for groups
	groupDN string
}

// Start creates and starts a running Directory ldap server.
// Support options: WithPort, WithMTLS, WithNoTLS, WithDefaults,
// WithLogger.
//
// The Directory will be shutdown when the test and all its
// subtests are compted via a registered function with t.Cleanup(...)
func Start(t TestingT, opt ...Option) *Directory {
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(t)
	opts := getOpts(t, opt...)
	if opts.withPort == 0 {
		opts.withPort = FreePort(t)
	}
	// Handle IPv6 addresses
	if strings.Contains(opts.withHost, ":") && !strings.ContainsAny(opts.withHost, "[]") {
		opts.withHost = "[" + opts.withHost + "]"
	}

	d := &Directory{
		t:                  t,
		logger:             opts.withLogger,
		users:              opts.withDefaults.Users,
		groups:             opts.withDefaults.Groups,
		port:               opts.withPort,
		host:               opts.withHost,
		userDN:             opts.withDefaults.UserDN,
		groupDN:            opts.withDefaults.GroupDN,
		allowAnonymousBind: opts.withDefaults.AllowAnonymousBind,
	}

	var err error
	var srvOpts []gldap.Option
	if opts.withLogger != nil {
		srvOpts = append(srvOpts, gldap.WithLogger(opts.withLogger))
	}
	if opts.withDisablePanicRecovery {
		srvOpts = append(srvOpts, gldap.WithDisablePanicRecovery())
	}
	d.s, err = gldap.NewServer(srvOpts...)
	require.NoError(err)

	d.logger.Debug("base search DNs", "users", d.userDN, "groups", d.groupDN)

	mux, err := gldap.NewMux()
	require.NoError(err)
	require.NoError(mux.DefaultRoute(d.handleNotFound(t)))
	require.NoError(mux.Bind(d.handleBind(t)))
	require.NoError(mux.ExtendedOperation(d.handleStartTLS(t), gldap.ExtendedOperationStartTLS))
	require.NoError(mux.Search(d.handleSearchUsers(t), gldap.WithBaseDN(d.userDN), gldap.WithLabel("Search - Users")))
	require.NoError(mux.Search(d.handleSearchGroups(t), gldap.WithBaseDN(d.groupDN), gldap.WithLabel("Search - Groups")))
	require.NoError(mux.Search(d.handleSearchGeneric(t), gldap.WithLabel("Search - Generic")))
	require.NoError(mux.Modify(d.handleModify(t), gldap.WithLabel("Modify")))
	require.NoError(mux.Add(d.handleAdd(t), gldap.WithLabel("Add")))
	require.NoError(mux.Delete(d.handleDelete(t), gldap.WithLabel("Delete")))

	require.NoError(d.s.Router(mux))

	serverTLSConfig, clientTLSConfig := GetTLSConfig(t, opt...)
	d.client = clientTLSConfig
	d.server = serverTLSConfig

	var connOpts []gldap.Option
	if !opts.withNoTLS {
		d.useTLS = true
		connOpts = append(connOpts, gldap.WithTLSConfig(d.server))
		if opts.withMTLS {
			d.logger.Debug("using mTLS")
		} else {
			d.logger.Debug("using TLS")
		}
	} else {
		d.logger.Debug("not using TLS")
	}
	go func() {
		err := d.s.Run(fmt.Sprintf("%s:%d", opts.withHost, opts.withPort), connOpts...)
		if err != nil {
			d.logger.Error("Error during shutdown", "op", "testdirectory.Start", "err", err.Error())
		}
	}()

	if v, ok := interface{}(t).(CleanupT); ok {
		v.Cleanup(func() { _ = d.s.Stop() })
	}
	// need a bit of a pause to get the service up and running, otherwise we'll
	// get a connection error because the service isn't listening yet.
	for {
		time.Sleep(100 * time.Nanosecond)
		if d.s.Ready() {
			break
		}
	}
	return d
}

// Stop will stop the Directory if it wasn't started with a *testing.T
// if it was started with *testing.T then Stop() is ignored.
func (d *Directory) Stop() {
	const op = "testdirectory.(Directory).Stop"
	if _, ok := interface{}(d.t).(CleanupT); !ok {
		err := d.s.Stop()
		if err != nil {
			d.logger.Error("error stopping directory: %s", "op", op, "err", err)
			return
		}
	}
}

// handleBind is ONLY supporting simple authentication (no SASL here!)
func (d *Directory) handleBind(t TestingT) func(w *gldap.ResponseWriter, r *gldap.Request) {
	const op = "testdirectory.(Directory).handleBind"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		d.logger.Debug(op)
		resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
		defer func() {
			_ = w.Write(resp)
		}()
		m, err := r.GetSimpleBindMessage()
		if err != nil {
			d.logger.Error("not a simple bind message", "op", op, "err", err)
			return
		}

		if m.AuthChoice != gldap.SimpleAuthChoice {
			// if it's not a simple auth request, then the bind failed...
			return
		}
		if m.Password == "" && d.allowAnonymousBind {
			resp.SetResultCode(gldap.ResultSuccess)
			return
		}

		for _, u := range d.users {
			d.logger.Debug("user", "u.DN", u.DN, "m.UserName", m.UserName)
			if u.DN == m.UserName {
				d.logger.Debug("found bind user", "op", op, "DN", u.DN)
				values := u.GetAttributeValues("password")
				if len(values) > 0 && string(m.Password) == values[0] {
					resp.SetResultCode(gldap.ResultSuccess)
					if d.controls != nil {
						d.mu.Lock()
						defer d.mu.Unlock()
						resp.SetControls(d.controls...)
					}
					return
				}
			}
		}
		// bind failed...
		return //nolint:gosimple // (ignore redundant return)
	}
}

func (d *Directory) handleNotFound(t TestingT) func(w *gldap.ResponseWriter, r *gldap.Request) {
	const op = "testdirectory.(Directory).handleNotFound"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		d.logger.Debug(op)
		resp := r.NewResponse(gldap.WithDiagnosticMessage("intentionally not handled"))
		_ = w.Write(resp)
		return //nolint:gosimple // (ignore redundant return)
	}
}

func (d *Directory) handleStartTLS(t TestingT) func(w *gldap.ResponseWriter, r *gldap.Request) {
	const op = "testdirectory.(Directory).handleStartTLS"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		d.logger.Debug(op)
		res := r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultSuccess))
		res.SetResponseName(gldap.ExtendedOperationStartTLS)
		err := w.Write(res)
		if err != nil {
			d.logger.Error("error writing response: %s", "op", op, "err", err)
			return
		}
		if err := r.StartTLS(d.server); err != nil {
			d.logger.Error("StartTLS Handshake error", "op", op, "err", err)
			res.SetDiagnosticMessage(fmt.Sprintf("StartTLS Handshake error : \"%s\"", err.Error()))
			res.SetResultCode(gldap.ResultOperationsError)
			err := w.Write(res)
			if err != nil {
				d.logger.Error("error writing response: %s", "op", op, "err", err)
				return
			}
			return
		}
		d.logger.Debug("StartTLS OK", "op", op)
	}
}

func (d *Directory) handleSearchGeneric(t TestingT) func(w *gldap.ResponseWriter, r *gldap.Request) {
	const op = "testdirectory.(Directory).handleSearchGeneric"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		d.logger.Debug(op)
		res := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
		defer func() {
			err := w.Write(res)
			if err != nil {
				d.logger.Error("error writing response: %s", "op", op, "err", err)
				return
			}
		}()
		m, err := r.GetSearchMessage()
		if err != nil {
			d.logger.Error("not a search message: %s", "op", op, "err", err)
			return
		}
		d.logSearchRequest(m)

		filter := m.Filter

		// if our search base is the base userDN, we're searching for a single
		// user, so adjust the filter to match user's entries
		if strings.Contains(string(m.BaseDN), d.userDN) {
			filter = fmt.Sprintf("(%s)", m.BaseDN)
			d.logger.Debug("new filter", "op", op, "value", filter)
			for _, a := range m.Attributes {
				d.logger.Debug("attr", "op", op, "value", a)
				if a == "tokenGroups" {
					d.logger.Debug("asking for groups", "op", op)
				}
			}
		}

		var foundEntries int

		// if our search base is a SID, then we're searching for tokenGroups
		if len(d.tokenGroups) > 0 && strings.HasPrefix(string(m.BaseDN), "<SID=") {
			sid := string(m.BaseDN)
			sid = strings.TrimPrefix(sid, "<SID=")
			sid = strings.TrimSuffix(sid, ">")
			for _, g := range d.tokenGroups[sid] {
				d.logger.Debug("found tokenGroup", "op", op, "group DN", g.DN)
				result := r.NewSearchResponseEntry(g.DN)
				for _, attr := range g.Attributes {
					result.AddAttribute(attr.Name, attr.Values)
				}
				foundEntries += 1
				err = w.Write(result)
				if err != nil {
					d.logger.Error("error writing result: %s", "op", op, "err", err)
					return
				}
			}
			d.logger.Debug("found entries", "op", op, "count", foundEntries)
			res.SetResultCode(gldap.ResultSuccess)
			return
		}

		d.logger.Debug("filter", "op", op, "value", filter)
		var entries []*gldap.Entry
		for _, e := range d.users {
			if ok, _ := match(filter, e.DN); !ok {
				continue
			}
			entries = append(entries, e)
			foundEntries += 1
		}
		for _, e := range d.groups {
			if ok, _ := match(filter, e.DN); !ok {
				continue
			}
			switch {
			case slices.Contains(entries, e):
				continue
			default:
				entries = append(entries, e)
				foundEntries += 1
			}
		}
		if foundEntries > 0 {
			d.logger.Debug("found entries", "op", op, "count", foundEntries)
			for _, e := range entries {
				result := r.NewSearchResponseEntry(e.DN)
				for _, attr := range e.Attributes {
					result.AddAttribute(attr.Name, attr.Values)
				}
				foundEntries += 1
				err := w.Write(result)
				if err != nil {
					d.logger.Error("error writing result: %s", "op", op, "err", err)
					return
				}
			}
			if d.controls != nil {
				d.mu.Lock()
				defer d.mu.Unlock()
				res.SetControls(d.controls...)
			}
			res.SetResultCode(gldap.ResultSuccess)
		}
	}
}

func (d *Directory) handleSearchGroups(t TestingT) func(w *gldap.ResponseWriter, r *gldap.Request) {
	const op = "testdirectory.(Directory).handleSearchGroups"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		d.logger.Debug(op)
		res := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
		defer func() {
			err := w.Write(res)
			if err != nil {
				d.logger.Error("error writing result: %s", "op", op, "err", err)
				return
			}
		}()
		m, err := r.GetSearchMessage()
		if err != nil {
			d.logger.Error("not a search message: %s", "op", op, "err", err)
			return
		}
		d.logSearchRequest(m)

		_, entries := d.findMembers(m.Filter)
		foundEntries := len(entries)

		for _, e := range d.groups {
			if ok, _ := match(m.Filter, e.DN); !ok {
				continue
			}
			switch {
			case slices.Contains(entries, e):
				continue
			default:
				entries = append(entries, e)
			}
			foundEntries += 1
		}

		if foundEntries > 0 {
			for _, e := range entries {
				result := r.NewSearchResponseEntry(e.DN)
				for _, attr := range e.Attributes {
					result.AddAttribute(attr.Name, attr.Values)
				}
				foundEntries += 1
				err = w.Write(result)
				if err != nil {
					d.logger.Error("error writing result: %s", "op", op, "err", err)
					return
				}
			}
			d.logger.Debug("found entries", "op", op, "count", foundEntries)

			if d.controls != nil {
				d.mu.Lock()
				defer d.mu.Unlock()
				res.SetControls(d.controls...)
			}
			res.SetResultCode(gldap.ResultSuccess)
		}
	}
}

func (d *Directory) handleSearchUsers(t TestingT) func(w *gldap.ResponseWriter, r *gldap.Request) {
	const op = "testdirectory.(Directory).handleSearchUsers"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		d.logger.Debug(op)
		res := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
		defer func() {
			err := w.Write(res)
			if err != nil {
				d.logger.Error("error writing result: %s", "op", op, "err", err)
				return
			}
		}()
		m, err := r.GetSearchMessage()
		if err != nil {
			d.logger.Error("not a search message: %s", "op", op, "err", err)
			return
		}
		d.logSearchRequest(m)

		var foundEntries int
		_, _, entries := find(d.t, m.Filter, d.users)
		if len(entries) == 0 {
			return
		}
		for _, e := range entries {
			result := r.NewSearchResponseEntry(e.DN)
			for _, attr := range e.Attributes {
				result.AddAttribute(attr.Name, attr.Values)
			}
			foundEntries += 1
			err := w.Write(result)
			if err != nil {
				d.logger.Error("error writing result: %s", "op", op, "err", err)
				return
			}
		}
		if foundEntries > 0 {
			d.logger.Debug("found entries", "op", op, "count", foundEntries)
			if d.controls != nil {
				d.mu.Lock()
				defer d.mu.Unlock()
				res.SetControls(d.controls...)
				fmt.Println(d.controls)
			}
			res.SetResultCode(gldap.ResultSuccess)
		}
	}
}

func (d *Directory) handleModify(t TestingT) func(w *gldap.ResponseWriter, r *gldap.Request) {
	const op = "testdirectory.(Directory).handleModify"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		d.logger.Debug(op)
		res := r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
		defer func() {
			err := w.Write(res)
			if err != nil {
				d.logger.Error("error writing result: %s", "op", op, "err", err)
				return
			}
		}()
		m, err := r.GetModifyMessage()
		if err != nil {
			d.logger.Error("not a modify message: %s", "op", op, "err", err)
			return
		}
		d.logger.Info("modify request", "dn", m.DN)

		var entries []*gldap.Entry
		_, _, entries = find(d.t, fmt.Sprintf("(%s)", m.DN), d.users)
		if len(entries) == 0 {
			_, _, entries = find(d.t, m.DN, d.groups)
		}
		if len(entries) == 0 {
			return
		}
		if len(entries) > 1 {
			res.SetResultCode(gldap.ResultInappropriateMatching)
			res.SetDiagnosticMessage(fmt.Sprintf("more than one match: %d entries", len(entries)))
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		e := entries[0]
		if entries[0].Attributes == nil {
			e.Attributes = []*gldap.EntryAttribute{}
		}
		res.SetMatchedDN(entries[0].DN)
		for _, chg := range m.Changes {
			// find specific attr
			var foundAttr *gldap.EntryAttribute
			var foundAt int
			for i, a := range e.Attributes {
				if a.Name == chg.Modification.Type {
					foundAttr = a
					foundAt = i
				}
			}
			// then apply operation
			switch chg.Operation {
			case gldap.AddAttribute:
				if foundAttr != nil {
					foundAttr.AddValue(chg.Modification.Vals...)
				} else {
					e.Attributes = append(e.Attributes, gldap.NewEntryAttribute(chg.Modification.Type, chg.Modification.Vals))
				}
			case gldap.DeleteAttribute:
				if foundAttr != nil {
					// slice out the deleted attribute
					copy(e.Attributes[foundAt:], e.Attributes[foundAt+1:])
					e.Attributes = e.Attributes[:len(e.Attributes)-1]
				}
			case gldap.ReplaceAttribute:
				if foundAttr != nil {
					// we're updating what the ptr points at, so disable lint of
					// unused var
					//nolint:staticcheck
					foundAttr = gldap.NewEntryAttribute(chg.Modification.Type, chg.Modification.Vals)
				}
			}
		}
		res.SetResultCode(gldap.ResultSuccess)
	}
}

func (d *Directory) handleAdd(t TestingT) func(w *gldap.ResponseWriter, r *gldap.Request) {
	const op = "testdirectory.(Directory).handleAdd"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		d.logger.Debug(op)
		res := r.NewResponse(gldap.WithApplicationCode(gldap.ApplicationAddResponse), gldap.WithResponseCode(gldap.ResultOperationsError))
		defer func() {
			err := w.Write(res)
			if err != nil {
				d.logger.Error("error writing result: %s", "op", op, "err", err)
				return
			}
		}()
		m, err := r.GetAddMessage()
		if err != nil {
			d.logger.Error("not an add message: %s", "op", op, "err", err)
			return
		}
		d.logger.Info("add request", "dn", m.DN)

		if found, _, _ := find(d.t, fmt.Sprintf("(%s)", m.DN), d.users); found {
			res.SetResultCode(gldap.ResultEntryAlreadyExists)
			res.SetDiagnosticMessage(fmt.Sprintf("entry exists for DN: %s", m.DN))
			return
		}
		attrs := map[string][]string{}
		for _, a := range m.Attributes {
			attrs[a.Type] = a.Vals
		}
		newEntry := gldap.NewEntry(m.DN, attrs)
		d.mu.Lock()
		defer d.mu.Unlock()
		d.users = append(d.users, newEntry)
		res.SetResultCode(gldap.ResultSuccess)
	}
}

func (d *Directory) handleDelete(t TestingT) func(w *gldap.ResponseWriter, r *gldap.Request) {
	const op = "testdirectory.(Directory).handleDelete"
	if v, ok := interface{}(t).(HelperT); ok {
		v.Helper()
	}
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		d.logger.Debug(op)
		res := r.NewResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject), gldap.WithApplicationCode(gldap.ApplicationDelResponse))
		defer func() {
			err := w.Write(res)
			if err != nil {
				d.logger.Error("error writing response: %s", "op", op, "err", err)
				return
			}
		}()
		m, err := r.GetDeleteMessage()
		if err != nil {
			d.logger.Error("not a delete message: %s", "op", op, "err", err)
			return
		}
		d.logger.Info("delete request", "dn", m.DN)

		_, foundAt, _ := find(d.t, fmt.Sprintf("(%s)", m.DN), d.users)
		if len(foundAt) > 0 {
			if len(foundAt) > 1 {
				res.SetResultCode(gldap.ResultInappropriateMatching)
				res.SetDiagnosticMessage(fmt.Sprintf("more than one match: %d entries", len(foundAt)))
				return
			}
			d.mu.Lock()
			defer d.mu.Unlock()
			d.users = append(d.users[:foundAt[0]], d.users[foundAt[0]+1:]...)
			res.SetResultCode(gldap.ResultSuccess)
			return
		}
		_, foundAt, _ = find(d.t, fmt.Sprintf("(%s)", m.DN), d.groups)
		if len(foundAt) > 0 {
			if len(foundAt) > 1 {
				res.SetResultCode(gldap.ResultInappropriateMatching)
				res.SetDiagnosticMessage(fmt.Sprintf("more than one match: %d entries", len(foundAt)))
				return
			}
			d.mu.Lock()
			defer d.mu.Unlock()
			d.groups = append(d.groups[:foundAt[0]], d.groups[foundAt[0]+1:]...)
			res.SetResultCode(gldap.ResultSuccess)
			return
		}
		return //nolint:gosimple // (ignore redundant return)
	}
}

func (d *Directory) findMembers(filter string, opt ...Option) (bool, []*gldap.Entry) {
	opts := getOpts(d.t, opt...)
	var matches []*gldap.Entry
	for _, e := range d.groups {
		members := e.GetAttributeValues("member")
		for _, m := range members {
			if ok, _ := match(filter, "member="+m); ok {
				matches = append(matches, e)
				if opts.withFirst {
					return true, matches
				}
			}
		}
	}
	if len(matches) > 0 {
		return true, matches
	}
	return false, nil
}

func find(t TestingT, filter string, entries []*gldap.Entry, opt ...Option) (bool, []int, []*gldap.Entry) {
	opts := getOpts(t, opt...)
	var matches []*gldap.Entry
	var matchIndexes []int
	for idx, e := range entries {
		if ok, _ := match(filter, e.DN); ok {
			matches = append(matches, e)
			matchIndexes = append(matchIndexes, idx)
			if opts.withFirst {
				return true, []int{idx}, matches
			}
		}
	}
	if len(matches) > 0 {
		return true, matchIndexes, matches
	}
	return false, nil, nil
}

func match(filter string, attr string) (bool, error) {
	// TODO: make this actually do something more reasonable with the search
	// request filter
	re := regexp.MustCompile(`\((.*?)\)`)
	submatchall := re.FindAllString(filter, -1)
	for _, element := range submatchall {
		element = strings.ReplaceAll(element, "*", "")
		element = strings.Trim(element, "|(")
		element = strings.Trim(element, "(")
		element = strings.Trim(element, ")")
		element = strings.TrimSpace(element)
		if strings.Contains(attr, element) {
			return true, nil
		}
	}
	return false, nil
}

// Conn returns an *ldap.Conn that's connected (using whatever tls.Config is
// appropriate for the directory) and ready send requests to the directory.
func (d *Directory) Conn() *ldap.Conn {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(d.t)

	var conn *ldap.Conn
	retryAttempt := 5
	retryErrFn := func(e error) error {
		if retryAttempt > 0 {
			fmt.Println(retryAttempt)
			retryAttempt--
			return backoff.Permanent(e)
		}
		return backoff.Permanent(e)
	}
	err := backoff.Retry(func() error {
		var connErr error
		if d.useTLS {
			if conn, connErr = ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", d.Host(), d.Port()), ldap.DialWithTLSConfig(d.client)); connErr != nil {
				return retryErrFn(connErr)
			}
			return nil
		}
		if conn, connErr = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", d.Host(), d.Port())); connErr != nil {
			return retryErrFn(connErr)
		}
		return nil
	}, backoff.NewConstantBackOff(1*time.Second))
	require.NoError(err)
	return conn
}

// Cert returns the pem-encoded certificate used by the Directory.
func (d *Directory) Cert() string {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(d.t)

	require.NotNil(d.server)
	require.Len(d.server.Certificates, 1)
	cert := d.server.Certificates[0]
	require.NotNil(cert)
	require.Len(cert.Certificate, 1)
	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	require.NoError(err)
	return buf.String()
}

// Port returns the port the directory is listening on
func (d *Directory) Port() int {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	return d.port
}

// Host returns the host the directory is listening on
func (d *Directory) Host() string {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	return d.host
}

// ClientCert returns the pem-encoded certificate which can be used by a client
// for mTLS.
func (d *Directory) ClientCert() string {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(d.t)

	require.NotNil(d.client)
	require.Len(d.client.Certificates, 1)
	cert := d.client.Certificates[0]
	require.NotNil(cert)
	require.Len(cert.Certificate, 1)
	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	require.NoError(err)
	return buf.String()
}

// ClientKey returns the pem-encoded private key which can be used by a client
// for mTLS.
func (d *Directory) ClientKey() string {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	require := require.New(d.t)

	require.NotNil(d.client)
	require.Len(d.client.Certificates, 1)
	privBytes, err := x509.MarshalPKCS8PrivateKey(d.client.Certificates[0].PrivateKey)
	require.NoError(err)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	require.NotNil(pemKey)
	return string(pemKey)
}

// Controls returns all the current bind controls for the Directory
func (d *Directory) Controls() []gldap.Control {
	return d.controls
}

// SetControls sets the bind controls.
func (d *Directory) SetControls(controls ...gldap.Control) {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.controls = controls
}

// Users returns all the current user entries in the Directory
func (d *Directory) Users() []*gldap.Entry {
	return d.users
}

// SetUsers sets the user entries.
func (d *Directory) SetUsers(users ...*gldap.Entry) {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users = users
}

// Groups returns all the current group entries in the Directory
func (d *Directory) Groups() []*gldap.Entry {
	return d.groups
}

// SetGroups sets the group entries.
func (d *Directory) SetGroups(groups ...*gldap.Entry) {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.groups = groups
}

// SetTokenGroups will set the tokenGroup entries.
func (d *Directory) SetTokenGroups(tokenGroups map[string][]*gldap.Entry) {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokenGroups = tokenGroups
}

// TokenGroups will return the tokenGroup entries
func (d *Directory) TokenGroups() map[string][]*gldap.Entry {
	return d.tokenGroups
}

// AllowAnonymousBind returns the allow anon bind setting
func (d *Directory) AllowAnonymousBind() bool {
	return d.allowAnonymousBind
}

// SetAllowAnonymousBind enables/disables anon binds
func (d *Directory) SetAllowAnonymousBind(enabled bool) {
	if v, ok := interface{}(d.t).(HelperT); ok {
		v.Helper()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.allowAnonymousBind = enabled
}

func (d *Directory) logSearchRequest(m *gldap.SearchMessage) {
	d.logger.Info("search request",
		"baseDN", m.BaseDN,
		"scope", m.Scope,
		"filter", m.Filter,
		"attributes", m.Attributes,
	)
}
