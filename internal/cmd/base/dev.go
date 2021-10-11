package base

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/cmd/base/internal/docker"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/schema"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/observability/event"
	hostplugin "github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/testing/dbtest"
	capoidc "github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/go-multierror"
)

func (b *Server) CreateDevDatabase(ctx context.Context, opt ...Option) error {
	const op = "base.(Server).CreateDevDatabase"
	var container, url, dialect string
	var err error
	var c func() error

	opts := getOpts(opt...)

	// We should only get back postgres for now, but laying the foundation for non-postgres
	switch opts.withDialect {
	case "":
		event.WriteError(ctx, op, err, event.WithInfoMsg("unsupported dialect", "wanted", "postgres", "got", opts.withDialect))
	default:
		dialect = opts.withDialect
	}

	switch b.DatabaseUrl {
	case "":
		if opts.withDatabaseTemplate != "" {
			c, url, _, err = dbtest.StartUsingTemplate(dialect, dbtest.WithTemplate(opts.withDatabaseTemplate))
		} else {
			c, url, container, err = docker.StartDbInDocker(dialect, docker.WithContainerImage(opts.withContainerImage))
		}
		// In case of an error, run the cleanup function.  If we pass all errors, c should be set to a noop
		// function before returning from this method
		defer func() {
			if !opts.withSkipDatabaseDestruction {
				if c != nil {
					if err := c(); err != nil {
						event.WriteError(ctx, op, err, event.WithInfoMsg("error cleaning up docker container"))
					}
				}
			}
		}()
		if err == docker.ErrDockerUnsupported {
			return err
		}
		if err != nil {
			return fmt.Errorf("unable to start dev database with dialect %s: %w", dialect, err)
		}

		// Let migrate store manage the dirty bit since dev DBs should be ephemeral anyways.
		_, err := schema.MigrateStore(ctx, schema.Dialect(dialect), url)
		if err != nil {
			err = fmt.Errorf("unable to initialize dev database with dialect %s: %w", dialect, err)
			if c != nil {
				err = multierror.Append(err, c())
			}
			return err
		}

		b.DevDatabaseCleanupFunc = c
		b.DatabaseUrl = url
	default:
		// Let migrate store manage the dirty bit since dev DBs should be ephemeral anyways.
		if _, err := schema.MigrateStore(ctx, schema.Dialect(dialect), b.DatabaseUrl); err != nil {
			err = fmt.Errorf("error initializing store: %w", err)
			if c != nil {
				err = multierror.Append(err, c())
			}
			return err
		}
	}

	b.InfoKeys = append(b.InfoKeys, "dev database url")
	b.Info["dev database url"] = b.DatabaseUrl
	if container != "" {
		b.InfoKeys = append(b.InfoKeys, "dev database container")
		b.Info["dev database container"] = strings.TrimPrefix(container, "/")
	}

	if err := b.ConnectToDatabase(ctx, dialect); err != nil {
		if c != nil {
			err = multierror.Append(err, c())
		}
		return err
	}

	if err := b.CreateGlobalKmsKeys(ctx); err != nil {
		if c != nil {
			err = multierror.Append(err, c())
		}
		return err
	}

	if _, err := b.CreateInitialLoginRole(ctx); err != nil {
		if c != nil {
			err = multierror.Append(err, c())
		}
		return err
	}

	if opts.withSkipAuthMethodCreation {
		// now that we have passed all the error cases, reset c to be a noop so the
		// defer doesn't do anything.
		c = func() error { return nil }
		return nil
	}

	if _, _, err := b.CreateInitialPasswordAuthMethod(ctx); err != nil {
		return err
	}

	if !opts.withSkipOidcAuthMethodCreation {
		if err := b.CreateDevOidcAuthMethod(ctx); err != nil {
			return err
		}
	}

	if opts.withSkipScopesCreation {
		// now that we have passed all the error cases, reset c to be a noop so the
		// defer doesn't do anything.
		c = func() error { return nil }
		return nil
	}

	if _, _, err := b.CreateInitialScopes(ctx); err != nil {
		return err
	}

	if opts.withHostPlugin != nil {
		pluginId, plg := opts.withHostPlugin()
		b.DevLoopbackHostPluginId = pluginId
		opts := []hostplugin.Option{
			hostplugin.WithDescription("Provides an initial loopback host plugin in Boundary"),
			hostplugin.WithPublicId(b.DevLoopbackHostPluginId),
		}
		if _, err = b.CreateHostPlugin(ctx, "loopback", plg, opts...); err != nil {
			return err
		}
	}

	if opts.withSkipHostResourcesCreation {
		// now that we have passed all the error cases, reset c to be a noop so the
		// defer doesn't do anything.
		c = func() error { return nil }
		return nil
	}

	if _, _, _, err := b.CreateInitialHostResources(context.Background()); err != nil {
		return err
	}

	if opts.withSkipTargetCreation {
		// now that we have passed all the error cases, reset c to be a noop so the
		// defer doesn't do anything.
		c = func() error { return nil }
		return nil
	}

	if _, err := b.CreateInitialTarget(ctx); err != nil {
		return err
	}

	// now that we have passed all the error cases, reset c to be a noop so the
	// defer doesn't do anything.
	c = func() error { return nil }
	return nil
}

type oidcSetup struct {
	clientId     string
	clientSecret oidc.ClientSecret
	oidcPort     int
	callbackPort string
	hostAddr     string
	authMethod   *oidc.AuthMethod
	pubKey       []byte
	privKey      []byte
	testProvider *capoidc.TestProvider
	createUnpriv bool
	callbackUrl  *url.URL
}

func (b *Server) CreateDevOidcAuthMethod(ctx context.Context) error {
	var err error

	if b.DevOidcAuthMethodId == "" {
		b.DevOidcAuthMethodId, err = db.NewPublicId(oidc.AuthMethodPrefix)
		if err != nil {
			return fmt.Errorf("error generating initial oidc auth method id: %w", err)
		}
	}
	b.InfoKeys = append(b.InfoKeys, "generated oidc auth method id")
	b.Info["generated oidc auth method id"] = b.DevOidcAuthMethodId

	switch {
	case b.DevUnprivilegedLoginName == "",
		b.DevUnprivilegedPassword == "",
		b.DevUnprivilegedUserId == "",
		b.DevUnprivilegedOidcAccountId == "":

	default:
		b.DevOidcSetup.createUnpriv = true
	}

	// Trawl through the listeners and find the api listener so we can use the
	// same host name/IP
	{
		for _, ln := range b.Listeners {
			purpose := strings.ToLower(ln.Config.Purpose[0])
			if purpose != "api" {
				continue
			}
			b.DevOidcSetup.hostAddr, b.DevOidcSetup.callbackPort, err = net.SplitHostPort(ln.Config.Address)
			if err != nil {
				if strings.Contains(err.Error(), "missing port") {
					b.DevOidcSetup.hostAddr = ln.Config.Address
					// Use the default API port in the callback
					b.DevOidcSetup.callbackPort = "9200"
				} else {
					return fmt.Errorf("error splitting host/port: %w", err)
				}
			}
		}
		if b.DevOidcSetup.hostAddr == "" {
			return fmt.Errorf("could not determine address to use for built-in oidc dev listener")
		}
	}

	// Find an available port -- allocate one, then close the listener, and
	// re-use it. This is a sort of hacky way to get around the chicken and egg
	// of the auth method needing to know the discovery URL and the test
	// provider needing to know the callback URL.
	l, err := net.Listen("tcp", net.JoinHostPort(b.DevOidcSetup.hostAddr, "0"))
	if err != nil {
		return fmt.Errorf("error finding port for oidc test provider: %w", err)
	}
	b.DevOidcSetup.oidcPort = l.(*net.TCPListener).Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		return fmt.Errorf("error closing initial test port: %w", err)
	}
	b.DevOidcSetup.callbackUrl, err = url.Parse(fmt.Sprintf("http://%s", net.JoinHostPort(b.DevOidcSetup.hostAddr, b.DevOidcSetup.callbackPort)))
	if err != nil {
		return fmt.Errorf("error parsing oidc test provider callback url: %w", err)
	}

	// Generate initial IDs/keys
	{
		b.DevOidcSetup.clientId, err = capoidc.NewID()
		if err != nil {
			return fmt.Errorf("unable to generate client id: %w", err)
		}
		clientSecret, err := capoidc.NewID()
		if err != nil {
			return fmt.Errorf("unable to generate client secret: %w", err)
		}
		b.DevOidcSetup.clientSecret = oidc.ClientSecret(clientSecret)
		b.DevOidcSetup.pubKey, b.DevOidcSetup.privKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			return fmt.Errorf("unable to generate signing key: %w", err)
		}
	}

	// Create the subject information and testing provider
	{

		subInfo := map[string]*capoidc.TestSubject{
			b.DevLoginName: {
				Password: b.DevPassword,
				UserInfo: map[string]interface{}{
					"email": "admin@localhost",
					"name":  "Admin User",
				},
			},
		}
		if b.DevOidcSetup.createUnpriv {
			subInfo[b.DevUnprivilegedLoginName] = &capoidc.TestSubject{
				Password: b.DevUnprivilegedPassword,
				UserInfo: map[string]interface{}{
					"email": "user@localhost",
					"name":  "Unprivileged User",
				},
			}
		}

		clientSecret := string(b.DevOidcSetup.clientSecret)

		b.DevOidcSetup.testProvider = capoidc.StartTestProvider(
			&oidcLogger{},
			capoidc.WithNoTLS(),
			capoidc.WithTestHost(b.DevOidcSetup.hostAddr),
			capoidc.WithTestPort(b.DevOidcSetup.oidcPort),
			capoidc.WithTestDefaults(&capoidc.TestProviderDefaults{
				CustomClaims: map[string]interface{}{
					"mode": "dev",
				},
				SubjectInfo: subInfo,
				SigningKey: &capoidc.TestSigningKey{
					PrivKey: ed25519.PrivateKey(b.DevOidcSetup.privKey),
					PubKey:  ed25519.PublicKey(b.DevOidcSetup.pubKey),
					Alg:     capoidc.EdDSA,
				},
				AllowedRedirectURIs: []string{fmt.Sprintf("%s/v1/auth-methods/oidc:authenticate:callback", b.DevOidcSetup.callbackUrl.String())},
				ClientID:            &b.DevOidcSetup.clientId,
				ClientSecret:        &clientSecret,
			}))

		b.ShutdownFuncs = append(b.ShutdownFuncs, func() error {
			b.DevOidcSetup.testProvider.Stop()
			return nil
		})
	}

	// Create auth method and link accounts
	{
		b.DevOidcSetup.authMethod, err = b.createInitialOidcAuthMethod(ctx)
		if err != nil {
			return fmt.Errorf("error creating initial oidc auth method: %w", err)
		}
	}

	return nil
}

func (b *Server) createInitialOidcAuthMethod(ctx context.Context) (*oidc.AuthMethod, error) {
	rw := db.New(b.Database)

	kmsRepo, err := kms.NewRepository(rw, rw)
	if err != nil {
		return nil, fmt.Errorf("error creating kms repository: %w", err)
	}
	kmsCache, err := kms.NewKms(kmsRepo)
	if err != nil {
		return nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := kmsCache.AddExternalWrappers(
		kms.WithRootWrapper(b.RootKms),
	); err != nil {
		return nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	discoveryUrl, err := url.Parse(fmt.Sprintf("http://%s:%d", b.DevOidcSetup.hostAddr, b.DevOidcSetup.oidcPort))
	if err != nil {
		return nil, fmt.Errorf("error parsing oidc test provider address: %w", err)
	}

	// Create the auth method
	oidcRepo, err := oidc.NewRepository(ctx, rw, rw, kmsCache)
	if err != nil {
		return nil, fmt.Errorf("error creating oidc repo: %w", err)
	}

	authMethod, err := oidc.NewAuthMethod(
		ctx,
		scope.Global.String(),
		b.DevOidcSetup.clientId,
		b.DevOidcSetup.clientSecret,
		oidc.WithName("Generated global scope initial oidc auth method"),
		oidc.WithDescription("Provides initial administrative and unprivileged authentication into Boundary"),
		oidc.WithIssuer(discoveryUrl),
		oidc.WithApiUrl(b.DevOidcSetup.callbackUrl),
		oidc.WithSigningAlgs(oidc.EdDSA),
		oidc.WithOperationalState(oidc.ActivePublicState))
	if err != nil {
		return nil, fmt.Errorf("error creating new in memory oidc auth method: %w", err)
	}
	if b.DevOidcAuthMethodId == "" {
		b.DevOidcAuthMethodId, err = db.NewPublicId(oidc.AuthMethodPrefix)
		if err != nil {
			return nil, fmt.Errorf("error generating initial oidc auth method id: %w", err)
		}
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-b.ShutdownCh:
			cancel()
		case <-cancelCtx.Done():
		}
	}()

	b.DevOidcSetup.authMethod, err = oidcRepo.CreateAuthMethod(
		cancelCtx,
		authMethod,
		oidc.WithPublicId(b.DevOidcAuthMethodId))
	if err != nil {
		return nil, fmt.Errorf("error saving oidc auth method to the db: %w", err)
	}

	// Create accounts
	{
		createAndLinkAccount := func(loginName, userId, accountId, typ string) error {
			acct, err := oidc.NewAccount(
				ctx,
				b.DevOidcSetup.authMethod.GetPublicId(),
				loginName,
				oidc.WithDescription(fmt.Sprintf("Initial %s OIDC account", typ)),
			)
			if err != nil {
				return fmt.Errorf("error generating %s oidc account: %w", typ, err)
			}
			acct, err = oidcRepo.CreateAccount(
				cancelCtx,
				b.DevOidcSetup.authMethod.GetScopeId(),
				acct,
				oidc.WithPublicId(accountId),
			)
			if err != nil {
				return fmt.Errorf("error creating %s oidc account: %w", typ, err)
			}

			// Link accounts to existing user
			iamRepo, err := iam.NewRepository(rw, rw, kmsCache)
			if err != nil {
				return fmt.Errorf("unable to create iam repo: %w", err)
			}

			u, _, err := iamRepo.LookupUser(cancelCtx, userId)
			if err != nil {
				return fmt.Errorf("error looking up %s user: %w", typ, err)
			}
			if _, err = iamRepo.AddUserAccounts(cancelCtx, u.GetPublicId(), u.GetVersion(), []string{acct.GetPublicId()}); err != nil {
				return fmt.Errorf("error associating initial %s user with account: %w", typ, err)
			}

			return nil
		}

		if err := createAndLinkAccount(b.DevLoginName, b.DevUserId, b.DevOidcAccountId, "admin"); err != nil {
			return nil, err
		}
		if b.DevOidcSetup.createUnpriv {
			if err := createAndLinkAccount(b.DevUnprivilegedLoginName, b.DevUnprivilegedUserId, b.DevUnprivilegedOidcAccountId, "unprivileged"); err != nil {
				return nil, err
			}
		}
	}

	return nil, nil
}

// oidcLogger satisfies the interface requirements for the oidc.TestProvider logger.
type oidcLogger struct {
	Ctx context.Context // nil ctx is allowed/okay
}

// Errorf will use the sys eventer to emit an error event
func (l *oidcLogger) Errorf(format string, args ...interface{}) {
	event.WriteError(l.Ctx, l.caller(), fmt.Errorf(format, args...))
}

// Infof will use the sys eventer to emit an system event
func (l *oidcLogger) Infof(format string, args ...interface{}) {
	event.WriteSysEvent(l.Ctx, l.caller(), fmt.Sprintf(format, args...))
}

// FailNow will panic (as required by the interface it's implementing)
func (_ *oidcLogger) FailNow() {
	panic("sys eventer failed, see logs for output (if any)")
}

func (_ *oidcLogger) caller() event.Op {
	var caller event.Op
	pc, _, _, ok := runtime.Caller(2)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		caller = event.Op(details.Name())
	} else {
		caller = "unknown operation"
	}
	return caller
}
