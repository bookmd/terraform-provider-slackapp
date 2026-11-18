package vault_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflogtest"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/vault"
)

const testToken = "vscrt_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type call struct {
	method, path, authorization, accountID string
	body                                   map[string]any
}

// fakeVim answers /app-auth/token and the vault secret routes, and records
// each call.
type fakeVim struct {
	*httptest.Server

	mu       sync.Mutex
	calls    []call
	minted   int
	statuses map[string][]int
	// retryAfter makes every failure answer carry a Retry-After header.
	retryAfter bool
}

func newFakeVim(t *testing.T) *fakeVim {
	t.Helper()

	f := &fakeVim{statuses: map[string][]int{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		f.mu.Lock()
		f.calls = append(f.calls, call{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("X-Account-Id"), body})
		key := r.Method + " " + r.URL.Path
		status := http.StatusOK
		if queued := f.statuses[key]; len(queued) > 0 {
			status, f.statuses[key] = queued[0], queued[1:]
		}
		if r.URL.Path == "/app-auth/token" && status == http.StatusOK {
			f.minted++
		}
		minted, retryAfter := f.minted, f.retryAfter
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		switch {
		case status >= 400:
			if retryAfter {
				w.Header().Set("Retry-After", "0")
			}
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"error":"Conflict","message":"failed with %d"}`, status)
		case r.URL.Path == "/app-auth/token":
			_, _ = fmt.Fprintf(w, `{"access_token":"access-%d","token_type":"Bearer","expires_in":3600}`, minted)
		default:
			fields := []string{}
			if f, ok := body["fields"].(map[string]any); ok {
				for name := range f {
					fields = append(fields, name)
				}
			}
			consumers, _ := body["consumers"].([]any)
			if r.Method == http.MethodPost && r.URL.Path == "/api/vault/secrets" {
				w.WriteHeader(http.StatusCreated)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"token": testToken, "name": body["name"], "fields": fields, "consumers": consumers})
		}
	}))
	t.Cleanup(f.Close)

	return f
}

func (f *fakeVim) failNext(method, path string, statuses ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.statuses[method+" "+path] = append(f.statuses[method+" "+path], statuses...)
}

func (f *fakeVim) recorded() []call {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]call(nil), f.calls...)
}

func (f *fakeVim) target() vault.Target {
	return vault.Target{BaseURL: f.URL + "/", AccountID: "acc-1"}
}

func client() *vault.Client {
	return vault.NewClient("client-id", "client-secret-value").WithRetryWait(time.Millisecond)
}

func TestCreateRotateAndShare(t *testing.T) {
	t.Parallel()

	f := newFakeVim(t)
	c := client()
	ctx := t.Context()

	secret, err := c.CreateSecret(ctx, f.target(), vault.CreateSecretRequest{
		Name: "slack-app/jim", AuthKind: "custom",
		Fields: vault.Fields{"botToken": "xoxb-1", "signingSecret": "sig-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if secret.Token != testToken || len(secret.Fields) != 2 {
		t.Errorf("created %+v", secret)
	}

	if _, err := c.RotateSecret(ctx, f.target(), testToken, vault.RotateSecretRequest{AuthKind: "custom", Fields: vault.Fields{"botToken": "xoxb-2"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetConsumers(ctx, f.target(), testToken, nil); err != nil {
		t.Fatal(err)
	}

	calls := f.recorded()
	got := []string{}
	for _, c := range calls {
		got = append(got, c.method+" "+c.path)
	}
	want := []string{
		"POST /app-auth/token",
		"POST /api/vault/secrets",
		"PATCH /api/vault/secrets/" + testToken,
		"PUT /api/vault/secrets/" + testToken + "/consumers",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	mint := calls[0].body
	if mint["grant_type"] != "client_credentials" || mint["client_id"] != "client-id" ||
		mint["client_secret"] != "client-secret-value" || mint["account_id"] != "acc-1" {
		t.Errorf("token request %v", mint)
	}

	for _, c := range calls[1:] {
		if c.authorization != "Bearer access-1" || c.accountID != "acc-1" {
			t.Errorf("%s %s sent Authorization %q, x-account-id %q", c.method, c.path, c.authorization, c.accountID)
		}
	}

	if consumers, ok := calls[1].body["consumers"].([]any); !ok || len(consumers) != 0 {
		t.Errorf("create sent consumers %v, want []", calls[1].body["consumers"])
	}
	if consumers, ok := calls[3].body["consumers"].([]any); !ok || len(consumers) != 0 {
		t.Errorf("set consumers sent %v, want []", calls[3].body["consumers"])
	}
}

func TestConflict(t *testing.T) {
	t.Parallel()

	f := newFakeVim(t)
	f.failNext(http.MethodPost, "/api/vault/secrets", http.StatusConflict)

	_, err := client().CreateSecret(t.Context(), f.target(), vault.CreateSecretRequest{Name: "n", AuthKind: "custom", Fields: vault.Fields{"a": "b"}})
	if !vault.IsConflict(err) {
		t.Fatalf("error %v, want a conflict", err)
	}
	if !strings.Contains(err.Error(), "HTTP 409: failed with 409") {
		t.Errorf("error %q lacks the status and message", err)
	}
	if n := len(f.recorded()); n != 2 {
		t.Errorf("%d calls, want 2: a conflict is not sent again", n)
	}
}

func TestRetriesWhatVimDidNotTake(t *testing.T) {
	t.Parallel()

	f := newFakeVim(t)
	f.mu.Lock()
	f.retryAfter = true
	f.mu.Unlock()
	f.failNext(http.MethodPost, "/api/vault/secrets", http.StatusServiceUnavailable, http.StatusTooManyRequests)

	if _, err := client().CreateSecret(t.Context(), f.target(), vault.CreateSecretRequest{Name: "n", AuthKind: "custom", Fields: vault.Fields{"a": "b"}}); err != nil {
		t.Fatal(err)
	}
	if n := len(f.recorded()); n != 4 {
		t.Errorf("%d calls, want 4: a token and three creates", n)
	}
}

func TestGivesUpAfterThreeAttempts(t *testing.T) {
	t.Parallel()

	f := newFakeVim(t)
	f.failNext(http.MethodPut, "/api/vault/secrets/"+testToken+"/consumers", 502, 502, 502, 502)

	_, err := client().SetConsumers(t.Context(), f.target(), testToken, []string{"agentflow:staging/jim"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("error %v, want HTTP 502", err)
	}
	if n := len(f.recorded()); n != 4 {
		t.Errorf("%d calls, want 4: a token and three writes", n)
	}
}

func TestDoesNotRetryARefusal(t *testing.T) {
	t.Parallel()

	f := newFakeVim(t)
	f.failNext(http.MethodPatch, "/api/vault/secrets/"+testToken, http.StatusForbidden)

	_, err := client().RotateSecret(t.Context(), f.target(), testToken, vault.RotateSecretRequest{AuthKind: "custom", Fields: vault.Fields{"a": "b"}})
	if err == nil || vault.IsConflict(err) || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("error %v, want a 403", err)
	}
	if n := len(f.recorded()); n != 2 {
		t.Errorf("%d calls, want 2", n)
	}
}

// After a 401 the access token is dropped, and the next write mints another.
func TestUnauthorizedMintsAgain(t *testing.T) {
	t.Parallel()

	f := newFakeVim(t)
	f.failNext(http.MethodPatch, "/api/vault/secrets/"+testToken, http.StatusUnauthorized)
	c := client()

	if _, err := c.RotateSecret(t.Context(), f.target(), testToken, vault.RotateSecretRequest{AuthKind: "custom", Fields: vault.Fields{"a": "b"}}); err == nil {
		t.Fatal("rotate succeeded, want 401")
	}
	if _, err := c.RotateSecret(t.Context(), f.target(), testToken, vault.RotateSecretRequest{AuthKind: "custom", Fields: vault.Fields{"a": "b"}}); err != nil {
		t.Fatal(err)
	}

	calls := f.recorded()
	if last := calls[len(calls)-1]; last.authorization != "Bearer access-2" {
		t.Errorf("second rotate sent %q, want a newly minted token", last.authorization)
	}
}

func TestMintFails(t *testing.T) {
	t.Parallel()

	f := newFakeVim(t)
	f.failNext(http.MethodPost, "/app-auth/token", http.StatusUnauthorized)

	_, err := client().SetConsumers(t.Context(), f.target(), testToken, nil)
	if err == nil || !strings.Contains(err.Error(), "mint a Vim access token") {
		t.Fatalf("error %v", err)
	}
}

func TestNoCredentials(t *testing.T) {
	t.Parallel()

	f := newFakeVim(t)
	_, err := vault.NewClient("", "").SetConsumers(t.Context(), f.target(), testToken, nil)
	if err == nil || !strings.Contains(err.Error(), "vim_client_id") {
		t.Fatalf("error %v", err)
	}
	if n := len(f.recorded()); n != 0 {
		t.Errorf("%d calls, want none", n)
	}
}

func TestLogsNoSecrets(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	ctx := tflogtest.RootLogger(t.Context(), &buf)
	f := newFakeVim(t)

	_, err := client().CreateSecret(ctx, f.target(), vault.CreateSecretRequest{
		Name: "n", AuthKind: "custom", Fields: vault.Fields{"botToken": "xoxb-loggedvalue"},
	})
	if err != nil {
		t.Fatal(err)
	}

	logs, _ := io.ReadAll(&buf)
	for _, secret := range []string{"xoxb-loggedvalue", "client-secret-value", "access-1"} {
		if bytes.Contains(logs, []byte(secret)) {
			t.Errorf("the log contains %q", secret)
		}
	}
	if !bytes.Contains(logs, []byte(testToken)) {
		t.Error("the log does not name the secret token")
	}
	if s := fmt.Sprint(vault.Fields{"a": "b"}); s != "[redacted]" {
		t.Errorf("fields print as %q", s)
	}
}

func createRequest() vault.CreateSecretRequest {
	return vault.CreateSecretRequest{Name: "n", AuthKind: "custom", Fields: vault.Fields{"a": "b"}}
}

// A create Vim may have taken is not sent again: a second create of a secret
// that did land answers 409.
func TestCreateIsNotRepeatedWhenVimMayHaveTakenIt(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable} {
		f := newFakeVim(t)
		f.failNext(http.MethodPost, "/api/vault/secrets", status)

		if _, err := client().CreateSecret(t.Context(), f.target(), createRequest()); err == nil {
			t.Fatalf("HTTP %d: create succeeded", status)
		}
		if n := len(f.recorded()); n != 2 {
			t.Errorf("HTTP %d: %d calls, want 2: a token and one create", status, n)
		}
	}
}

func TestConflictAfterRetry(t *testing.T) {
	t.Parallel()

	f := newFakeVim(t)
	f.failNext(http.MethodPost, "/api/vault/secrets", http.StatusTooManyRequests, http.StatusConflict)

	_, err := client().CreateSecret(t.Context(), f.target(), createRequest())
	if !vault.IsConflictAfterRetry(err) || !vault.IsConflict(err) {
		t.Fatalf("error %v, want a conflict after a retry", err)
	}

	f = newFakeVim(t)
	f.failNext(http.MethodPost, "/api/vault/secrets", http.StatusConflict)

	if _, err := client().CreateSecret(t.Context(), f.target(), createRequest()); vault.IsConflictAfterRetry(err) {
		t.Errorf("a first-attempt conflict %v reads as one after a retry", err)
	}
}

// fakeVimServing answers the token mint, and every vault write with serve.
func fakeVimServing(t *testing.T, serve http.HandlerFunc) (vault.Target, func() int) {
	t.Helper()

	var mu sync.Mutex
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app-auth/token" {
			_, _ = fmt.Fprint(w, `{"access_token":"access","expires_in":3600}`)

			return
		}
		mu.Lock()
		writes++
		mu.Unlock()
		serve(w, r)
	}))
	t.Cleanup(server.Close)

	return vault.Target{BaseURL: server.URL, AccountID: "acc-1"}, func() int {
		mu.Lock()
		defer mu.Unlock()

		return writes
	}
}

func TestCreateIsNotRepeatedAfterANetworkFailure(t *testing.T) {
	t.Parallel()

	target, writes := fakeVimServing(t, func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the test server cannot drop a connection")

			return
		}
		if connection, _, err := hijacker.Hijack(); err == nil {
			_ = connection.Close()
		}
	})

	if _, err := client().CreateSecret(t.Context(), target, createRequest()); err == nil {
		t.Fatal("create succeeded")
	}
	if n := writes(); n != 1 {
		t.Errorf("%d creates, want 1", n)
	}
}

// A success answer that is not a secret means Vim took the write.
func TestUnreadableSuccessIsNotRepeated(t *testing.T) {
	t.Parallel()

	target, writes := fakeVimServing(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "not json")
	})
	c := client()

	if _, err := c.CreateSecret(t.Context(), target, createRequest()); err == nil || !strings.Contains(err.Error(), "not a secret") {
		t.Fatalf("create error %v", err)
	}
	if _, err := c.RotateSecret(t.Context(), target, testToken, vault.RotateSecretRequest{AuthKind: "custom", Fields: vault.Fields{"a": "b"}}); err == nil {
		t.Fatal("rotate succeeded")
	}
	if n := writes(); n != 2 {
		t.Errorf("%d writes, want 2: one create and one rotate", n)
	}
}

// The client credentials and the access token never follow a redirect.
func TestDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	elsewhere := newFakeVim(t)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)

	_, err := client().SetConsumers(t.Context(), vault.Target{BaseURL: redirecting.URL, AccountID: "acc-1"}, testToken, nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("error %v, want HTTP 307", err)
	}
	if n := len(elsewhere.recorded()); n != 0 {
		t.Errorf("the redirect target got %d calls", n)
	}

	target, _ := fakeVimServing(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	if _, err := client().RotateSecret(t.Context(), target, testToken, vault.RotateSecretRequest{AuthKind: "custom", Fields: vault.Fields{"a": "b"}}); err == nil {
		t.Fatal("rotate followed a redirect")
	}
	if n := len(elsewhere.recorded()); n != 0 {
		t.Errorf("the redirect target got %d calls", n)
	}
}
