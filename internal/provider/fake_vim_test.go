package provider_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeVim serves /app-auth/token and the vault secret routes the Vim
// platform app may call. Like the real vault, it refuses a second secret of
// the same name and offers no way to read one back; tests read it from the
// fake.
//
//declscope:shared // vim_app_test.go runs every test against one
type fakeVim struct {
	//declscope:private
	server *httptest.Server

	//declscope:private
	mu sync.Mutex
	//declscope:private
	secrets map[string]*fakeVimSecret
	//declscope:private
	calls []string
	//declscope:private
	failures map[string]int
}

type fakeVimSecret struct {
	name string
	//declscope:shared
	fields map[string]string
	//declscope:shared
	consumers []string
}

//declscope:shared
func newFakeVim(t *testing.T) *fakeVim {
	t.Helper()

	f := &fakeVim{secrets: map[string]*fakeVimSecret{}, failures: map[string]int{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)

	return f
}

//declscope:shared
func (f *fakeVim) baseURL() string {
	return f.server.URL
}

// failWith makes every later call of route ("POST /api/vault/secrets")
// answer status.
//
//declscope:shared
func (f *fakeVim) failWith(route string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.failures[route] = status
}

//declscope:shared
func (f *fakeVim) succeed(route string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.failures, route)
}

// secret returns the secret named name, and its token.
//
//declscope:shared
func (f *fakeVim) secret(name string) (string, *fakeVimSecret) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for token, secret := range f.secrets {
		if secret.name == name {
			return token, secret
		}
	}

	return "", nil
}

// routes returns the vault routes called, in order, without the token mint.
//
//declscope:shared
func (f *fakeVim) routes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.calls)
}

func (f *fakeVim) serveHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GrantType string            `json:"grant_type"`
		AccountID string            `json:"account_id"`
		Name      string            `json:"name"`
		Fields    map[string]string `json:"fields"`
		Consumers []string          `json:"consumers"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	f.mu.Lock()
	defer f.mu.Unlock()

	if r.URL.Path == "/app-auth/token" {
		if body.GrantType != "client_credentials" || body.AccountID != "acc-1" {
			w.WriteHeader(http.StatusBadRequest)

			return
		}
		_, _ = fmt.Fprint(w, `{"access_token":"access","expires_in":3600}`)

		return
	}

	if r.Header.Get("Authorization") != "Bearer access" || r.Header.Get("X-Account-Id") != "acc-1" {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	route := r.Method + " " + r.URL.Path
	generic, token := route, ""
	if rest, ok := strings.CutPrefix(r.URL.Path, "/api/vault/secrets/"); ok {
		token = strings.TrimSuffix(rest, "/consumers")
		generic = strings.Replace(route, token, ":token", 1)
	}
	f.calls = append(f.calls, generic)

	if status, ok := f.failures[generic]; ok {
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, `{"error":"failed"}`)

		return
	}

	switch generic {
	case "POST /api/vault/secrets":
		for _, s := range f.secrets {
			if s.name == body.Name {
				w.WriteHeader(http.StatusConflict)
				_, _ = fmt.Fprintf(w, `{"message":"A vault secret named %q already exists"}`, body.Name)

				return
			}
		}
		token = fmt.Sprintf("vscrt_%x", sha256.Sum256([]byte(body.Name)))
		f.secrets[token] = &fakeVimSecret{name: body.Name, fields: body.Fields, consumers: body.Consumers}
		w.WriteHeader(http.StatusCreated)
	case "PATCH /api/vault/secrets/:token":
		if f.secrets[token] == nil {
			w.WriteHeader(http.StatusNotFound)

			return
		}
		f.secrets[token].fields = body.Fields
	case "PUT /api/vault/secrets/:token/consumers":
		if f.secrets[token] == nil {
			w.WriteHeader(http.StatusNotFound)

			return
		}
		f.secrets[token].consumers = body.Consumers
	default:
		w.WriteHeader(http.StatusForbidden)

		return
	}

	secret := f.secrets[token]
	fields := []string{}
	for name := range secret.fields {
		fields = append(fields, name)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "name": secret.name, "fields": fields, "consumers": secret.consumers})
}
