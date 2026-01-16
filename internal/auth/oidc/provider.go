// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"
	"strings"
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

// get determines if there's already a cached oidc.Provider for the
// current AuthMethod from the DB. The cached oidc.Provider is preferred since
// it maintains a cache of the JWKs required to verify ID Tokens from the IdP.
//
// Before returning a cached oidc.Provider, get ensures that the
// AuthMethod data used for the oidc.Provider's configuration hasn't changed
// since it was cached. This is necessary because another controller could
// update the AuthMethod in the DB, which would require changing the
// configuration of the cached provider.
//
// get will update the providerCache with the new AuthMethod, if it
// determines the provider's configuration has been updated in the DB.
func (c *providers) get(ctx context.Context, currentFromDb *AuthMethod) (*oidc.Provider, error) {
	const op = "oidc.(providers).getProvider"
	storedProvider, err := convertToProvider(ctx, currentFromDb)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.mu.RLock()
	p, ok := c.cache[currentFromDb.PublicId]
	c.mu.RUnlock()
	if ok {
		cachedHash, err := p.ConfigHash()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to hash provider from cache"))
		}
		storedHash, err := storedProvider.ConfigHash()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to hash provider from database"))
		}
		switch cachedHash == storedHash {
		case true:
			return p, nil
		default:
			c.delete(ctx, currentFromDb.PublicId)
		}
	}
	c.set(ctx, currentFromDb.PublicId, storedProvider)
	return storedProvider, nil
}

// set will set an entry in the cache.
func (c *providers) set(ctx context.Context, authMethodId string, p *oidc.Provider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[authMethodId] = p
}

// delete will delete an entry in the cache.
func (c *providers) delete(ctx context.Context, authMethodId string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, authMethodId)
}

func convertToProvider(ctx context.Context, am *AuthMethod) (*oidc.Provider, error) {
	const op = "oidc.convertToProvider"
	if am == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	}
	if err := am.isComplete(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	algs := make([]oidc.Alg, 0, len(am.SigningAlgs))
	for _, a := range am.SigningAlgs {
		algs = append(algs, oidc.Alg(a))
	}
	c, err := oidc.NewConfig(
		am.Issuer,
		am.ClientId,
		oidc.ClientSecret(am.ClientSecret),
		algs,
		[]string{fmt.Sprintf(CallbackEndpoint, am.GetApiUrl())},
		oidc.WithAudiences(am.AudClaims...),
		oidc.WithProviderCA(strings.Join(am.Certificates, "\n")),
	)
	if err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "AuthMethod cannot be converted to a valid OIDC Provider Configuration", errors.WithWrap(err))
	}
	p, err := oidc.NewProvider(c)
	if err != nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "AuthMethod cannot be converted to a valid OIDC Provider", errors.WithWrap(err))
	}
	return p, nil
}
