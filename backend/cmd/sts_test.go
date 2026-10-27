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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/auth"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/config"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/kubeconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd/api"
)

const stsTestExchangedToken = "google-access-token" // #nosec G101 -- synthetic test credential.

// stsTestJWT returns an unsigned JWT that expires in an hour.
func stsTestJWT(t *testing.T, subject string) string {
	t.Helper()

	payload, err := json.Marshal(map[string]interface{}{"sub": subject, "exp": time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)

	enc := base64.RawURLEncoding

	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

// stsTestServer is a fake STS that records the subject tokens it receives.
type stsTestServer struct {
	*httptest.Server
	mu       sync.Mutex
	subjects []string
	status   int
}

func newSTSTestServer(t *testing.T) *stsTestServer {
	t.Helper()

	sts := &stsTestServer{status: http.StatusOK}
	sts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())

		sts.mu.Lock()
		sts.subjects = append(sts.subjects, r.PostForm.Get("subject_token"))
		status := sts.status
		sts.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": stsTestExchangedToken, "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	t.Cleanup(sts.Close)

	return sts
}

func (s *stsTestServer) receivedSubjects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.subjects...)
}

// newSTSTestConfig returns a config with token exchange at sts for the
// in-cluster context "main". The kubeconfig context "other" has no exchange.
func newSTSTestConfig(t *testing.T, sts *stsTestServer, apiServerURL string) *HeadlampConfig {
	t.Helper()

	cfg := newDrainAuthConfig(t, &kubeconfig.Context{
		Name: "main", Source: kubeconfig.InCluster,
		Cluster:  &api.Cluster{Server: apiServerURL, InsecureSkipTLSVerify: true},
		AuthInfo: &api.AuthInfo{},
	})
	require.NoError(t, cfg.KubeConfigStore.AddContext(&kubeconfig.Context{
		Name: "other", Source: kubeconfig.KubeConfig,
		Cluster:  &api.Cluster{Server: apiServerURL, InsecureSkipTLSVerify: true},
		AuthInfo: &api.AuthInfo{},
	}))

	cfg.stsExchanger = auth.NewSTSExchanger(auth.STSConfig{
		TokenURL:           sts.URL,
		Audience:           "//iam.googleapis.com/locations/global/workforcePools/pool/providers/entra",
		SubjectTokenType:   config.DefaultOidcStsSubjectTokenType,
		RequestedTokenType: config.DefaultOidcStsRequestedTokenType,
	}, nil)

	t.Cleanup(func() { _ = cfg.stsExchanger.Close() })

	return cfg
}

// addAuthCookie adds the auth cookie of the "main" cluster.
func addAuthCookie(req *http.Request, token string) {
	req.AddCookie(&http.Cookie{
		Name: "headlamp-auth-main.0", Value: token,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// capturedRequest records what the handler after the middleware received.
type capturedRequest struct {
	called        bool
	authorization string
	cookies       map[string]string
	protocols     string
	exchanged     bool
}

func capturingHandler(captured *capturedRequest) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.called = true
		captured.authorization = r.Header.Get("Authorization")
		captured.protocols = r.Header.Get("Sec-Websocket-Protocol")
		captured.exchanged = stsExchanged(r)
		captured.cookies = map[string]string{}

		for _, cookie := range r.Cookies() {
			captured.cookies[cookie.Name] = cookie.Value
		}

		w.WriteHeader(http.StatusOK)
	})
}

func TestSTSTokenMiddlewareSendsExchangedTokenToAPIServer(t *testing.T) {
	var apiAuth, apiCookie string

	kubeAPI := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiAuth = r.Header.Get("Authorization")
		apiCookie = r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"PodList","items":[]}`))
	}))
	t.Cleanup(kubeAPI.Close)

	sts := newSTSTestServer(t)
	cfg := newSTSTestConfig(t, sts, kubeAPI.URL)

	router := mux.NewRouter()
	handleClusterAPI(cfg, router)

	userToken := stsTestJWT(t, "user")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/main/api/v1/pods", nil)
	addAuthCookie(req, userToken)
	req.AddCookie(&http.Cookie{
		Name: "headlamp-id-token-main.0", Value: "id-token",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})

	rr := httptest.NewRecorder()
	cfg.stsTokenMiddleware(router).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "Bearer "+stsTestExchangedToken, apiAuth)
	assert.NotContains(t, apiCookie, userToken, "the OIDC token must not reach the API server")
	assert.Contains(t, apiCookie, "headlamp-id-token-main.0=id-token")
	assert.Equal(t, []string{userToken}, sts.receivedSubjects())
}

func TestSTSTokenMiddlewareExchangesTokenForDrain(t *testing.T) {
	requests := make(chan string, 8)
	kubeAPI := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Header.Get("Authorization")

		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/pods" {
			_ = json.NewEncoder(w).Encode(corev1.PodList{})
		} else {
			_ = json.NewEncoder(w).Encode(corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "test-node"}})
		}
	}))
	t.Cleanup(kubeAPI.Close)

	sts := newSTSTestServer(t)
	cfg := newSTSTestConfig(t, sts, kubeAPI.URL)

	router := mux.NewRouter()
	handleClusterAPI(cfg, router)

	req, err := makeDrainJSONReq("/clusters/main/drain-node",
		map[string]string{"cluster": "main", "nodeName": "test-node"})
	require.NoError(t, err)
	addAuthCookie(req, stsTestJWT(t, "user"))

	rr := httptest.NewRecorder()
	cfg.stsTokenMiddleware(router).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	select {
	case got := <-requests:
		assert.Equal(t, "Bearer "+stsTestExchangedToken, got)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for drain request to reach Kubernetes API")
	}
}

func TestSTSTokenMiddlewareRejectsUnexchangedDrain(t *testing.T) {
	kubeAPI := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API request %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(kubeAPI.Close)

	sts := newSTSTestServer(t)
	cfg := newSTSTestConfig(t, sts, kubeAPI.URL)

	// The legacy route isn't under /clusters/<cluster>/, so the middleware
	// doesn't exchange its token. It must not be forwarded as is.
	req, err := makeDrainJSONReq("/drain-node", map[string]string{"cluster": "main", "nodeName": "test-node"})
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+stsTestJWT(t, "user"))

	rr := httptest.NewRecorder()
	cfg.stsTokenMiddleware(http.HandlerFunc(cfg.handleNodeDrain)).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Empty(t, sts.receivedSubjects())
}

func TestSTSTokenMiddlewareExchangesRefreshedToken(t *testing.T) {
	sts := newSTSTestServer(t)
	cfg := newSTSTestConfig(t, sts, "https://127.0.0.1:1")

	cookieToken := stsTestJWT(t, "old")
	refreshedToken := stsTestJWT(t, "refreshed")

	// The refresh middleware passes a refreshed token in the Authorization
	// header while the request still carries the old cookie.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/main/api/v1/pods", nil)
	req.Header.Set("Authorization", "Bearer "+refreshedToken)
	addAuthCookie(req, cookieToken)

	var captured capturedRequest

	cfg.stsTokenMiddleware(capturingHandler(&captured)).ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, []string{refreshedToken}, sts.receivedSubjects())
	assert.Equal(t, "Bearer "+stsTestExchangedToken, captured.authorization)
	assert.True(t, captured.exchanged)
}

func TestSTSTokenMiddlewareExchangesWebSocketProtocolToken(t *testing.T) {
	sts := newSTSTestServer(t)
	cfg := newSTSTestConfig(t, sts, "https://127.0.0.1:1")

	userToken := stsTestJWT(t, "user")
	encoded := base64.RawURLEncoding.EncodeToString([]byte(userToken))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/main/api/v1/pods?watch=1", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-Websocket-Protocol", "base64.binary.k8s.io, base64url.bearer.authorization.k8s.io."+encoded)

	var captured capturedRequest

	cfg.stsTokenMiddleware(capturingHandler(&captured)).ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, []string{userToken}, sts.receivedSubjects())
	assert.Equal(t, "Bearer "+stsTestExchangedToken, captured.authorization)
	assert.Equal(t, "base64.binary.k8s.io", captured.protocols)
}

func TestSTSTokenMiddlewareLeavesOtherRequestsAlone(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "me reads the OIDC token", path: "/clusters/main/me"},
		{name: "set-token", path: "/clusters/main/set-token"},
		{name: "context without exchange", path: "/clusters/other/api/v1/pods"},
		{name: "unknown context", path: "/clusters/missing/api/v1/pods"},
		{name: "not a cluster path", path: "/config"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sts := newSTSTestServer(t)
			cfg := newSTSTestConfig(t, sts, "https://127.0.0.1:1")

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tt.path, nil)
			req.Header.Set("Authorization", "Bearer header-token")
			addAuthCookie(req, "cookie-token")

			var captured capturedRequest

			cfg.stsTokenMiddleware(capturingHandler(&captured)).ServeHTTP(httptest.NewRecorder(), req)

			require.True(t, captured.called)
			assert.Equal(t, "Bearer header-token", captured.authorization)
			assert.Equal(t, "cookie-token", captured.cookies["headlamp-auth-main.0"])
			assert.False(t, captured.exchanged)
			assert.Empty(t, sts.receivedSubjects())
		})
	}
}

func TestSTSTokenMiddlewareHandlesBaseURL(t *testing.T) {
	sts := newSTSTestServer(t)
	cfg := newSTSTestConfig(t, sts, "https://127.0.0.1:1")
	cfg.BaseURL = "/headlamp"

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/headlamp/clusters/main/api/v1/pods", nil)
	addAuthCookie(req, stsTestJWT(t, "user"))

	var captured capturedRequest

	cfg.stsTokenMiddleware(capturingHandler(&captured)).ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "Bearer "+stsTestExchangedToken, captured.authorization)
	assert.NotContains(t, captured.cookies, "headlamp-auth-main.0")
}

func TestSTSTokenMiddlewareWithoutToken(t *testing.T) {
	sts := newSTSTestServer(t)
	cfg := newSTSTestConfig(t, sts, "https://127.0.0.1:1")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/main/api/v1/pods", nil)
	req.AddCookie(&http.Cookie{
		Name: "theme", Value: "dark",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})

	var captured capturedRequest

	cfg.stsTokenMiddleware(capturingHandler(&captured)).ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, captured.called)
	assert.Empty(t, captured.authorization)
	assert.Equal(t, map[string]string{"theme": "dark"}, captured.cookies)
	assert.False(t, captured.exchanged)
	assert.Empty(t, sts.receivedSubjects())
}

func TestSTSTokenMiddlewareExchangeErrors(t *testing.T) {
	tests := []struct {
		name       string
		stsStatus  int
		wantStatus int
	}{
		{name: "token rejected", stsStatus: http.StatusBadRequest, wantStatus: http.StatusUnauthorized},
		{name: "STS unavailable", stsStatus: http.StatusServiceUnavailable, wantStatus: http.StatusBadGateway},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sts := newSTSTestServer(t)
			sts.status = tt.stsStatus
			cfg := newSTSTestConfig(t, sts, "https://127.0.0.1:1")

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/main/api/v1/pods", nil)
			addAuthCookie(req, stsTestJWT(t, "user"))

			var captured capturedRequest

			rr := httptest.NewRecorder()
			cfg.stsTokenMiddleware(capturingHandler(&captured)).ServeHTTP(rr, req)

			assert.Equal(t, tt.wantStatus, rr.Code)
			assert.False(t, captured.called)
		})
	}
}

func TestSTSTokenMiddlewareDisabled(t *testing.T) {
	cfg := newDrainAuthConfig(t, &kubeconfig.Context{
		Name: "main", Source: kubeconfig.InCluster,
		Cluster: &api.Cluster{Server: "https://127.0.0.1:1"}, AuthInfo: &api.AuthInfo{},
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/main/api/v1/pods", nil)
	addAuthCookie(req, "cookie-token")

	var captured capturedRequest

	cfg.stsTokenMiddleware(capturingHandler(&captured)).ServeHTTP(httptest.NewRecorder(), req)

	assert.Empty(t, captured.authorization)
	assert.Equal(t, "cookie-token", captured.cookies["headlamp-auth-main.0"])
}

func TestServerHandlerExchangesRefreshedToken(t *testing.T) {
	var apiAuth string

	kubeAPI := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"PodList","items":[]}`))
	}))
	t.Cleanup(kubeAPI.Close)

	var issuer string

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": issuer, "token_endpoint": issuer + "/token",
				"authorization_endpoint": issuer + "/authorize", "jwks_uri": issuer + "/keys",
			})

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "renewed-user-token", "token_type": "Bearer",
			"refresh_token": "new-refresh", "expires_in": 3600,
		})
	}))
	t.Cleanup(provider.Close)
	issuer = provider.URL

	sts := newSTSTestServer(t)
	cfg := newSTSTestConfig(t, sts, kubeAPI.URL)
	kContext, err := cfg.KubeConfigStore.GetContext("main")
	require.NoError(t, err)

	kContext.OidcConf = &kubeconfig.OidcConfig{IdpIssuerURL: issuer, ClientID: "test-client"}
	cfg.OidcUseAccessToken = true
	cfg.SessionTTL = 3600
	cfg.TelemetryConfig = GetDefaultTestTelemetryConfig()

	// An expired token with a cached refresh token, so the refresh middleware renews it.
	oldToken := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1}`)) + ".signature"
	require.NoError(t, cfg.Cache.Set(context.Background(), "oidc-token-"+oldToken, "refresh-user-token"))

	handler, err := serverHandler(context.Background(), cfg)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/clusters/main/api/v1/pods", nil)
	addAuthCookie(req, oldToken)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []string{"renewed-user-token"}, sts.receivedSubjects(), "the refreshed token is exchanged")
	assert.Equal(t, "Bearer "+stsTestExchangedToken, apiAuth)
	assert.Contains(t, rr.Header().Get("Set-Cookie"), "renewed-user-token", "the cookie keeps the OIDC token")
}
