/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/kubernetes-sigs/headlamp/backend/pkg/auth"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/config"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/kubeconfig"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/logger"
)

// stsExchangedKey marks a request whose token was exchanged by stsTokenMiddleware.
type stsExchangedKey struct{}

// stsSkippedClusterPaths are cluster routes that need the user's own OIDC
// token rather than the exchanged one.
var stsSkippedClusterPaths = map[string]bool{
	"me":        true, // reads claims from the OIDC token
	"set-token": true, // stores a token, doesn't forward one
}

// newSTSExchanger creates the token exchanger configured by the oidc-sts-* flags,
// or returns nil if token exchange is off. conf must already be validated.
func newSTSExchanger(conf *config.Config) *auth.STSExchanger {
	if conf.OidcStsTokenURL == "" {
		return nil
	}

	extraParams, _ := config.ParseOidcStsExtraParams(conf.OidcStsExtraParams)

	var scopes []string

	for _, scope := range strings.Split(conf.OidcStsScopes, ",") {
		if scope = strings.TrimSpace(scope); scope != "" {
			scopes = append(scopes, scope)
		}
	}

	return auth.NewSTSExchanger(auth.STSConfig{
		TokenURL:           conf.OidcStsTokenURL,
		Audience:           conf.OidcStsAudience,
		Scopes:             scopes,
		SubjectTokenType:   conf.OidcStsSubjectTokenType,
		RequestedTokenType: conf.OidcStsRequestedTokenType,
		ExtraParams:        extraParams,
		ClientID:           conf.OidcStsClientID,
		ClientSecret:       conf.OidcStsClientSecret,
	}, nil)
}

// stsTokenMiddleware exchanges the user's token at the configured STS for
// requests to the in-cluster context. It runs after the OIDC refresh
// middleware, so it sees the refreshed token.
//
// The exchanged token is put in the Authorization header and the auth cookies
// are removed from the request, so no handler downstream can forward the
// user's OIDC token to the API server.
func (c *HeadlampConfig) stsTokenMiddleware(next http.Handler) http.Handler {
	if c.stsExchanger == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cluster, ok := c.stsClusterForPath(r.URL.Path)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		// Move a token sent as a WebSocket subprotocol into the Authorization
		// header, so it is exchanged like the others.
		processWebSocketProtocolHeader(r)

		// Same order as auth.ParseClusterAndToken: the refresh middleware puts a
		// refreshed token in the Authorization header.
		token := auth.BearerTokenValue(r.Header.Get("Authorization"))
		if token == "" {
			token, _ = auth.GetTokenFromCookie(r, cluster)
		}

		r.Header.Del("Authorization")
		removeAuthCookies(r)

		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		exchanged, err := c.stsExchanger.Exchange(r.Context(), token)
		if err != nil {
			logger.Log(logger.LevelError, map[string]string{"cluster": cluster}, err, "exchanging token with STS")

			if errors.Is(err, auth.ErrSTSRejected) {
				http.Error(w, "token exchange rejected", http.StatusUnauthorized)
			} else {
				http.Error(w, "token exchange failed", http.StatusBadGateway)
			}

			return
		}

		r.Header.Set("Authorization", "Bearer "+exchanged)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), stsExchangedKey{}, true)))
	})
}

// stsClusterForPath returns the cluster of a /clusters/<cluster>/... path if
// requests to it need token exchange: the cluster is the in-cluster context
// and the route isn't one that needs the OIDC token itself.
func (c *HeadlampConfig) stsClusterForPath(path string) (string, bool) {
	path = strings.TrimPrefix(path, strings.TrimRight(c.BaseURL, "/"))

	rest, ok := strings.CutPrefix(path, "/clusters/")
	if !ok {
		return "", false
	}

	cluster, route, _ := strings.Cut(rest, "/")
	if cluster == "" || stsSkippedClusterPaths[route] {
		return "", false
	}

	kContext, err := c.KubeConfigStore.GetContext(cluster)
	if err != nil || !c.usesSTS(kContext) {
		return "", false
	}

	return cluster, true
}

// usesSTS reports whether requests to kContext have their token exchanged.
func (c *HeadlampConfig) usesSTS(kContext *kubeconfig.Context) bool {
	return c.stsExchanger != nil && kContext != nil && kContext.Source == kubeconfig.InCluster
}

// stsExchanged reports whether stsTokenMiddleware exchanged the token of r.
func stsExchanged(r *http.Request) bool {
	exchanged, _ := r.Context().Value(stsExchangedKey{}).(bool)
	return exchanged
}

// removeAuthCookies removes every headlamp-auth-* cookie from the request.
func removeAuthCookies(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")

	for _, cookie := range cookies {
		if !strings.HasPrefix(cookie.Name, "headlamp-auth-") {
			r.AddCookie(cookie)
		}
	}
}
