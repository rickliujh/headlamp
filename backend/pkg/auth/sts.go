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

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/kubernetes-sigs/headlamp/backend/pkg/cache"
)

const (
	tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- grant type URN.
	// stsTimeout bounds a single exchange, independent of the requests waiting on it.
	stsTimeout = 10 * time.Second
	// stsExpirySkew is subtracted from the cache lifetime so a cached token is
	// never handed out right before it expires.
	stsExpirySkew = 30 * time.Second
	// stsMaxResponseBytes bounds how much of an STS response is read.
	stsMaxResponseBytes = 1 << 20
)

// ErrSTSRejected means the subject token was rejected, either by the STS or
// because it has already expired. The user needs to log in again.
var ErrSTSRejected = errors.New("subject token rejected")

// STSConfig configures an RFC 8693 token exchange.
type STSConfig struct {
	// TokenURL is the STS token endpoint, e.g. https://sts.googleapis.com/v1/token.
	TokenURL string
	// Audience identifies the target the exchanged token is for.
	Audience string
	// Scopes are sent space-separated in the scope parameter.
	Scopes             []string
	SubjectTokenType   string
	RequestedTokenType string
	// ExtraParams are added to the request form, e.g. Google's options parameter.
	ExtraParams url.Values
	// ClientID and ClientSecret, when set, are sent with HTTP Basic auth.
	ClientID     string
	ClientSecret string
}

// STSExchanger exchanges user tokens at an STS and caches the results.
type STSExchanger struct {
	config STSConfig
	client *http.Client
	cache  cache.Cache[string]
	group  singleflight.Group
}

// NewSTSExchanger creates an STSExchanger. If client is nil, a client with
// the system CAs and a 10 second timeout is used.
func NewSTSExchanger(config STSConfig, client *http.Client) *STSExchanger {
	if client == nil {
		client = &http.Client{Timeout: stsTimeout}
	}

	return &STSExchanger{
		config: config,
		client: client,
		cache:  cache.New[string](),
	}
}

// Exchange returns a token from the STS for the given subject token.
// Results are cached for at most the lifetime of the subject token.
func (e *STSExchanger) Exchange(ctx context.Context, subjectToken string) (string, error) {
	subjectExpiry, hasExpiry := tokenExpiry(subjectToken)
	if hasExpiry && !time.Now().Before(subjectExpiry) {
		return "", fmt.Errorf("%w: expired", ErrSTSRejected)
	}

	sum := sha256.Sum256([]byte(subjectToken))
	key := hex.EncodeToString(sum[:])

	if token, err := e.cache.Get(ctx, key); err == nil {
		return token, nil
	}

	// The exchange is shared by every request waiting for this key, so it must
	// not be cancelled when the request that started it goes away.
	result := e.group.DoChan(key, func() (interface{}, error) {
		exchangeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stsTimeout)
		defer cancel()

		token, expiresIn, err := e.requestToken(exchangeCtx, subjectToken)
		if err != nil {
			return "", err
		}

		if ttl := stsCacheTTL(time.Now(), expiresIn, subjectExpiry, hasExpiry); ttl > 0 {
			_ = e.cache.SetWithTTL(exchangeCtx, key, token, ttl)
		}

		return token, nil
	})

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-result:
		if res.Err != nil {
			return "", res.Err
		}

		return res.Val.(string), nil
	}
}

// Close stops the exchanger's cache.
func (e *STSExchanger) Close() error {
	return e.cache.Close()
}

// stsCacheTTL returns how long an exchanged token can be cached: until the
// earlier of its own expiry and the subject token's expiry, minus a skew.
// A non-positive result means the token must not be cached.
func stsCacheTTL(now time.Time, expiresIn time.Duration, subjectExpiry time.Time, hasSubjectExpiry bool) time.Duration {
	// Without the subject's expiry there's nothing to bound the cache by,
	// so every request is exchanged and the STS checks the subject itself.
	if !hasSubjectExpiry {
		return 0
	}

	ttl := subjectExpiry.Sub(now)
	if expiresIn > 0 && expiresIn < ttl {
		ttl = expiresIn
	}

	return ttl - stsExpirySkew
}

// tokenExpiry returns the exp claim of a JWT, if it has one.
func tokenExpiry(token string) (time.Time, bool) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return time.Time{}, false
	}

	payload, err := DecodeBase64JSON(parts[1])
	if err != nil {
		return time.Time{}, false
	}

	expiry, err := GetExpiryUnixTimeUTC(payload)
	if err != nil {
		return time.Time{}, false
	}

	return expiry, true
}

type stsTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

type stsErrorResponse struct {
	Error string `json:"error"`
}

// requestToken posts the token exchange request and returns the issued token
// and its lifetime (zero if the STS didn't say).
func (e *STSExchanger) requestToken(ctx context.Context, subjectToken string) (string, time.Duration, error) {
	req, err := e.newExchangeRequest(ctx, subjectToken)
	if err != nil {
		return "", 0, err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("calling STS: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, stsMaxResponseBytes))
	if err != nil {
		return "", 0, fmt.Errorf("reading STS response: %w", err)
	}

	return parseSTSResponse(resp.StatusCode, body)
}

// newExchangeRequest builds the RFC 8693 token exchange request.
func (e *STSExchanger) newExchangeRequest(ctx context.Context, subjectToken string) (*http.Request, error) {
	form := url.Values{}
	for name, values := range e.config.ExtraParams {
		form[name] = values
	}

	form.Set("grant_type", tokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", e.config.SubjectTokenType)
	form.Set("requested_token_type", e.config.RequestedTokenType)
	form.Set("audience", e.config.Audience)

	if len(e.config.Scopes) > 0 {
		form.Set("scope", strings.Join(e.config.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating STS request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if e.config.ClientID != "" {
		req.SetBasicAuth(url.QueryEscape(e.config.ClientID), url.QueryEscape(e.config.ClientSecret))
	}

	return req, nil
}

// parseSTSResponse returns the issued token and its lifetime from an STS response.
func parseSTSResponse(status int, body []byte) (string, time.Duration, error) {
	if status != http.StatusOK {
		// Only the error code is kept: descriptions can echo request details.
		var errResp stsErrorResponse

		_ = json.Unmarshal(body, &errResp)

		err := fmt.Errorf("STS returned status %d (error %q)", status, errResp.Error)

		switch status {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			return "", 0, fmt.Errorf("%w: %w", ErrSTSRejected, err)
		}

		return "", 0, err
	}

	var tokenResp stsTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("decoding STS response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", 0, errors.New("STS response has no access_token")
	}

	return tokenResp.AccessToken, time.Duration(tokenResp.ExpiresIn) * time.Second, nil
}
