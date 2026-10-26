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

package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubernetes-sigs/headlamp/backend/pkg/auth"
)

const (
	testIDTokenType     = "urn:ietf:params:oauth:token-type:id_token"     // #nosec G101 -- token type URN.
	testAccessTokenType = "urn:ietf:params:oauth:token-type:access_token" // #nosec G101 -- token type URN.
)

// testJWT returns an unsigned JWT with the given exp claim (none if zero).
func testJWT(t *testing.T, exp time.Time) string {
	t.Helper()

	claims := map[string]interface{}{"sub": "user@example.com"}
	if !exp.IsZero() {
		claims["exp"] = exp.Unix()
	}

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	enc := base64.RawURLEncoding

	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

// fakeSTS is an STS that records requests and answers with handler.
type fakeSTS struct {
	*httptest.Server
	hits atomic.Int32
}

func newFakeSTS(t *testing.T, handler http.HandlerFunc) *fakeSTS {
	t.Helper()

	sts := &fakeSTS{}
	sts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sts.hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(sts.Close)

	return sts
}

func respondToken(token string, expiresIn int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp := map[string]interface{}{
			"access_token":      token,
			"issued_token_type": testAccessTokenType,
			"token_type":        "Bearer",
		}
		if expiresIn > 0 {
			resp["expires_in"] = expiresIn
		}

		_ = json.NewEncoder(w).Encode(resp)
	}
}

func newTestExchanger(t *testing.T, tokenURL string, modify func(*auth.STSConfig)) *auth.STSExchanger {
	t.Helper()

	config := auth.STSConfig{
		TokenURL:           tokenURL,
		Audience:           "//iam.googleapis.com/locations/global/workforcePools/pool/providers/entra",
		SubjectTokenType:   testIDTokenType,
		RequestedTokenType: testAccessTokenType,
	}
	if modify != nil {
		modify(&config)
	}

	exchanger := auth.NewSTSExchanger(config, nil)

	t.Cleanup(func() { _ = exchanger.Close() })

	return exchanger
}

func TestSTSExchangerSendsTokenExchangeRequest(t *testing.T) {
	subject := testJWT(t, time.Now().Add(time.Hour))

	var form url.Values

	var authHeader, contentType string

	sts := newFakeSTS(t, func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())

		form = r.PostForm
		authHeader = r.Header.Get("Authorization")
		contentType = r.Header.Get("Content-Type")

		respondToken("google-token", 3600)(w, r)
	})

	exchanger := newTestExchanger(t, sts.URL, func(c *auth.STSConfig) {
		c.Scopes = []string{"https://www.googleapis.com/auth/cloud-platform", "openid"}
		c.ExtraParams = url.Values{"options": {`{"userProject":"123"}`}}
	})

	token, err := exchanger.Exchange(context.Background(), subject)
	require.NoError(t, err)

	assert.Equal(t, "google-token", token)
	assert.Equal(t, "application/x-www-form-urlencoded", contentType)
	assert.Empty(t, authHeader, "no client authentication unless configured")
	assert.Equal(t, url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {subject},
		"subject_token_type":   {testIDTokenType},
		"requested_token_type": {testAccessTokenType},
		"audience":             {"//iam.googleapis.com/locations/global/workforcePools/pool/providers/entra"},
		"scope":                {"https://www.googleapis.com/auth/cloud-platform openid"},
		"options":              {`{"userProject":"123"}`},
	}, form)
}

func TestSTSExchangerClientAuthentication(t *testing.T) {
	var user, password string

	var hasBasicAuth bool

	sts := newFakeSTS(t, func(w http.ResponseWriter, r *http.Request) {
		user, password, hasBasicAuth = r.BasicAuth()
		respondToken("sts-token", 3600)(w, r)
	})

	exchanger := newTestExchanger(t, sts.URL, func(c *auth.STSConfig) {
		c.ClientID = "sts-client"
		c.ClientSecret = "s3cret/+"
	})

	_, err := exchanger.Exchange(context.Background(), testJWT(t, time.Now().Add(time.Hour)))
	require.NoError(t, err)

	require.True(t, hasBasicAuth)
	// RFC 6749 section 2.3.1: client credentials are form-encoded before Basic auth.
	assert.Equal(t, "sts-client", user)
	assert.Equal(t, url.QueryEscape("s3cret/+"), password)
}

func TestSTSExchangerCacheLifetime(t *testing.T) {
	tests := []struct {
		name          string
		subjectExpiry time.Duration // zero means the subject token has no exp
		expiresIn     int
		wantHits      int32
	}{
		{name: "cached", subjectExpiry: time.Hour, expiresIn: 3600, wantHits: 1},
		{name: "cached without expires_in", subjectExpiry: time.Hour, expiresIn: 0, wantHits: 1},
		{
			// The exchanged token would be valid for an hour, but the subject
			// token expires within the expiry skew, so it isn't cached.
			name: "not cached past subject expiry", subjectExpiry: 20 * time.Second, expiresIn: 3600, wantHits: 2,
		},
		{name: "not cached when exchanged token is short lived", subjectExpiry: time.Hour, expiresIn: 10, wantHits: 2},
		{name: "not cached without subject expiry", subjectExpiry: 0, expiresIn: 3600, wantHits: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sts := newFakeSTS(t, respondToken("google-token", tt.expiresIn))
			exchanger := newTestExchanger(t, sts.URL, nil)

			var exp time.Time
			if tt.subjectExpiry != 0 {
				exp = time.Now().Add(tt.subjectExpiry)
			}

			subject := testJWT(t, exp)

			for range 2 {
				token, err := exchanger.Exchange(context.Background(), subject)
				require.NoError(t, err)
				assert.Equal(t, "google-token", token)
			}

			assert.Equal(t, tt.wantHits, sts.hits.Load())
		})
	}
}

func TestSTSExchangerCachesPerSubjectToken(t *testing.T) {
	var counter atomic.Int32

	sts := newFakeSTS(t, func(w http.ResponseWriter, r *http.Request) {
		respondToken(fmt.Sprintf("token-%d", counter.Add(1)), 3600)(w, r)
	})
	exchanger := newTestExchanger(t, sts.URL, nil)

	first, err := exchanger.Exchange(context.Background(), testJWT(t, time.Now().Add(time.Hour)))
	require.NoError(t, err)

	second, err := exchanger.Exchange(context.Background(), testJWT(t, time.Now().Add(2*time.Hour)))
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
	assert.Equal(t, int32(2), sts.hits.Load())
}

func TestSTSExchangerRejectsExpiredSubjectToken(t *testing.T) {
	sts := newFakeSTS(t, respondToken("google-token", 3600))
	exchanger := newTestExchanger(t, sts.URL, nil)

	_, err := exchanger.Exchange(context.Background(), testJWT(t, time.Now().Add(-time.Minute)))

	require.ErrorIs(t, err, auth.ErrSTSRejected)
	assert.Zero(t, sts.hits.Load(), "an expired token is rejected without calling the STS")
}

func TestSTSExchangerErrors(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantRejected bool
	}{
		{name: "bad request", status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`, wantRejected: true},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"error":"invalid_client"}`, wantRejected: true},
		{name: "forbidden", status: http.StatusForbidden, body: `{}`, wantRejected: true},
		{name: "rate limited", status: http.StatusTooManyRequests, body: `{}`},
		{name: "server error", status: http.StatusInternalServerError, body: `oops`},
		{name: "no access token", status: http.StatusOK, body: `{"expires_in":3600}`},
		{name: "invalid json", status: http.StatusOK, body: `not json`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sts := newFakeSTS(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			exchanger := newTestExchanger(t, sts.URL, nil)
			subject := testJWT(t, time.Now().Add(time.Hour))

			for range 2 {
				token, err := exchanger.Exchange(context.Background(), subject)
				require.Error(t, err)
				assert.Empty(t, token)
				assert.Equal(t, tt.wantRejected, errors.Is(err, auth.ErrSTSRejected))
				assert.NotContains(t, err.Error(), subject, "errors must not contain the token")
			}

			assert.Equal(t, int32(2), sts.hits.Load(), "errors are not cached")
		})
	}
}

// blockingSTS answers only after release is closed, and signals started on
// the first request.
func blockingSTS(t *testing.T) (*fakeSTS, chan struct{}, chan struct{}) {
	t.Helper()

	started := make(chan struct{})
	release := make(chan struct{})

	var once sync.Once

	sts := newFakeSTS(t, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		respondToken("google-token", 3600)(w, r)
	})

	return sts, started, release
}

func TestSTSExchangerSharesConcurrentExchanges(t *testing.T) {
	sts, started, release := blockingSTS(t)
	exchanger := newTestExchanger(t, sts.URL, nil)
	subject := testJWT(t, time.Now().Add(time.Hour))

	const callers = 5

	results := make(chan error, callers)

	for range callers {
		go func() {
			token, err := exchanger.Exchange(context.Background(), subject)
			if err == nil && token != "google-token" {
				err = fmt.Errorf("unexpected token %q", token)
			}

			results <- err
		}()
	}

	<-started
	close(release)

	for range callers {
		require.NoError(t, <-results)
	}

	// Callers either joined the one exchange or found its result in the cache.
	assert.Equal(t, int32(1), sts.hits.Load())
}

func TestSTSExchangerCancelledCallerDoesNotFailOthers(t *testing.T) {
	sts, started, release := blockingSTS(t)
	exchanger := newTestExchanger(t, sts.URL, nil)
	subject := testJWT(t, time.Now().Add(time.Hour))

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)

	go func() {
		_, err := exchanger.Exchange(firstCtx, subject)
		firstErr <- err
	}()

	<-started
	cancelFirst()
	require.ErrorIs(t, <-firstErr, context.Canceled)

	secondResult := make(chan error, 1)

	go func() {
		token, err := exchanger.Exchange(context.Background(), subject)
		if err == nil && token != "google-token" {
			err = fmt.Errorf("unexpected token %q", token)
		}

		secondResult <- err
	}()

	close(release)

	require.NoError(t, <-secondResult)
	assert.Equal(t, int32(1), sts.hits.Load(), "the first exchange kept running for the second caller")
}
