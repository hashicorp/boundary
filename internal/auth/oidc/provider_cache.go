package oidc

import (
	"context"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/cap/oidc"
)

var (
	// cachedProviders provides a cache of oidc.Providers. This cache can't be
	// done within the Repository, since a new Repository is created for every
	// request.
	cachedProviders     *providers
	initCachedProviders sync.Once
)

// providerCache returns the cache of providers
func providerCache() *providers {
	initCachedProviders.Do(func() {
		cachedProviders = newProviderCache()
	})
	return cachedProviders
}

// providers is a cache of oidc.Provider types used by the Repository to
// make requests to the IdP, verify ID tokens, etc.  For more info on
// oidc.Provider capabilities see: https://github.com/hashicorp/cap
type providers struct {
	cache map[string]*oidc.Provider
	mu    *sync.RWMutex
}

// newProviderCache make a new cache
func newProviderCache() *providers {
	return &providers{
		cache: map[string]*oidc.Provider{},
		mu:    &sync.RWMutex{},
	}
}

// getProvider determines if there's already a cached oidc.Provider for the
// current AuthMethod from the DB. The cached oidc.Provider is preferred since
// it maintains a cache of the JWKs required to verify ID Tokens from the IdP.
//
// Before returning a cached oidc.Provider, getProvider ensures that the
// AuthMethod data used for the oidc.Provider's configuration hasn't changed
// since it was cached. This is necessary because another controller could
// update the AuthMethod in the DB, which would require changing the
// configuration of the cached provider.
//
// getProvider will update the providerCache with the new AuthMethod, if it
// determines the provider's configuration has been updated in the DB.
func (c *providers) getProvider(ctx context.Context, currentFromDb *AuthMethod) (*oidc.Provider, error) {
	const op = "oidc.(Repository).getProvider"
	storedProvider, err := convertToProvider(ctx, currentFromDb)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	c.mu.RLock()
	p, ok := c.cache[currentFromDb.PublicId]
	c.mu.RUnlock()
	if ok {
		cachedHash, err := p.ConfigHash()
		if err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to hash provider from cache"))
		}
		storedHash, err := storedProvider.ConfigHash()
		if err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to hash provider from database"))
		}
		switch cachedHash == storedHash {
		case true:
			return p, nil
		default:
			c.delProvider(ctx, currentFromDb.PublicId)
		}
	}
	c.setProvider(ctx, currentFromDb.PublicId, storedProvider)
	return storedProvider, nil
}

// setProvider will set an entry in the cache.
func (c *providers) setProvider(ctx context.Context, authMethodId string, p *oidc.Provider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[authMethodId] = p
}

// delProvider will delete an entry in the cache.
func (c *providers) delProvider(ctx context.Context, authMethodId string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, authMethodId)
}
