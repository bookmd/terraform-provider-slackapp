// Package vault writes named secrets to a Vim account's vault, as a Vim
// platform app that holds client credentials.
//
// The platform app may create a secret, replace its fields and set the
// services it is shared with. It may not read, list or delete one, so a
// secret's values only ever travel from this package to the vault.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	// maxAttempts bounds the calls of one write that a failure Vim may not
	// repeat causes.
	maxAttempts = 3
	// tokenMargin is how long before its expiry an access token is replaced.
	tokenMargin = time.Minute
)

// Target is the Vim backend and the account whose vault a call writes to.
type Target struct {
	BaseURL   string
	AccountID string
}

func (t Target) url(path string) string {
	return strings.TrimSuffix(t.BaseURL, "/") + path
}

// Client calls the vault as one platform app. It mints an access token per
// target and reuses it until shortly before it expires.
type Client struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client
	retryWait    time.Duration

	mu     sync.Mutex
	tokens map[Target]accessToken
}

type accessToken struct {
	value     string
	expiresAt time.Time
}

func NewClient(clientID, clientSecret string) *Client {
	return &Client{
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   http.DefaultClient,
		retryWait:    2 * time.Second,
		tokens:       map[Target]accessToken{},
	}
}

// WithRetryWait sets the wait before a write is sent again, as the tests do
// to run fast.
func (c *Client) WithRetryWait(wait time.Duration) *Client {
	c.retryWait = wait

	return c
}

// StatusError is a call Vim answered with a status other than success.
type StatusError struct {
	Operation string
	Status    int
	Message   string
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s: Vim answered HTTP %d", e.Operation, e.Status)
	}

	return fmt.Sprintf("%s: Vim answered HTTP %d: %s", e.Operation, e.Status, e.Message)
}

// IsConflict reports whether err is Vim refusing a secret name the account
// already has.
func IsConflict(err error) bool {
	var statusErr *StatusError

	return errors.As(err, &statusErr) && statusErr.Status == http.StatusConflict
}

// Secret is what Vim returns for a secret it wrote: its name, the names of
// its fields and its consumers. Never a value.
type Secret struct {
	Token     string   `json:"token"`
	Name      string   `json:"name"`
	Fields    []string `json:"fields"`
	Consumers []string `json:"consumers"`
}

// Fields are a secret's values by field name. They print as [redacted].
type Fields map[string]string

func (Fields) String() string { return "[redacted]" }

func (Fields) GoString() string { return "[redacted]" }

type CreateSecretRequest struct {
	Name      string   `json:"name"`
	AuthKind  string   `json:"authKind"`
	Fields    Fields   `json:"fields"`
	Consumers []string `json:"consumers"`
}

// CreateSecret creates a named secret. Vim answers 409 when the account
// already has a secret of that name.
func (c *Client) CreateSecret(ctx context.Context, target Target, request CreateSecretRequest) (*Secret, error) {
	if request.Consumers == nil {
		request.Consumers = []string{}
	}

	return c.write(ctx, target, "create secret", http.MethodPost, "/api/vault/secrets", request)
}

type RotateSecretRequest struct {
	AuthKind string `json:"authKind"`
	Fields   Fields `json:"fields"`
}

// RotateSecret replaces every field of the secret.
func (c *Client) RotateSecret(ctx context.Context, target Target, token string, request RotateSecretRequest) (*Secret, error) {
	return c.write(ctx, target, "rotate secret", http.MethodPatch, "/api/vault/secrets/"+token, request)
}

// SetConsumers replaces the services the secret is shared with.
func (c *Client) SetConsumers(ctx context.Context, target Target, token string, consumers []string) (*Secret, error) {
	if consumers == nil {
		consumers = []string{}
	}

	return c.write(ctx, target, "set secret consumers", http.MethodPut, "/api/vault/secrets/"+token+"/consumers",
		map[string][]string{"consumers": consumers})
}

// write sends one vault write, and sends it again after a network failure or
// an answer that says Vim did not take it: 429 or 5xx.
func (c *Client) write(ctx context.Context, target Target, operation, method, path string, request any) (*Secret, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			tflog.Debug(ctx, "Sending the vault write again", map[string]any{"operation": operation, "attempt": attempt})
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.retryWait):
			}
		}

		var secret *Secret
		secret, lastErr = c.writeOnce(ctx, target, operation, method, path, body)
		if lastErr == nil || !retryable(lastErr) {
			return secret, lastErr
		}
	}

	return nil, lastErr
}

func retryable(err error) bool {
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return statusErr.Status == http.StatusTooManyRequests || statusErr.Status >= http.StatusInternalServerError
	}

	return true
}

func (c *Client) writeOnce(ctx context.Context, target Target, operation, method, path string, body []byte) (*Secret, error) {
	token, err := c.accessToken(ctx, target)
	if err != nil {
		return nil, err
	}

	httpRequest, err := http.NewRequestWithContext(ctx, method, target.url(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("X-Account-Id", target.AccountID)
	httpRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	defer func() { _ = httpResponse.Body.Close() }()

	if httpResponse.StatusCode == http.StatusUnauthorized {
		c.forgetToken(target)
	}

	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}

	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return nil, &StatusError{Operation: operation, Status: httpResponse.StatusCode, Message: errorMessage(responseBody)}
	}

	var secret Secret
	if err := json.Unmarshal(responseBody, &secret); err != nil {
		return nil, fmt.Errorf("%s: Vim answered HTTP %d with a body that is not a secret: %w", operation, httpResponse.StatusCode, err)
	}

	tflog.Debug(ctx, "Vim wrote the vault secret", map[string]any{
		"operation": operation, "status": httpResponse.StatusCode,
		"token": secret.Token, "fields": secret.Fields, "consumers": secret.Consumers,
	})

	return &secret, nil
}

// errorMessage takes the message from a Vim error body. A body is never
// echoed whole, so that nothing a request carried can reach a log.
func errorMessage(body []byte) string {
	var parsed struct {
		Error   any    `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return ""
	}
	if parsed.Message != "" {
		return parsed.Message
	}
	if text, ok := parsed.Error.(string); ok {
		return text
	}
	if object, ok := parsed.Error.(map[string]any); ok {
		if text, ok := object["message"].(string); ok {
			return text
		}
	}

	return ""
}

func (c *Client) forgetToken(target Target) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.tokens, target)
}

// accessToken returns a live access token for target, minting one with the
// client credentials when there is none.
func (c *Client) accessToken(ctx context.Context, target Target) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if token, ok := c.tokens[target]; ok && time.Now().Add(tokenMargin).Before(token.expiresAt) {
		return token.value, nil
	}

	if c.clientID == "" || c.clientSecret == "" {
		return "", errors.New("the provider has no Vim platform app client credentials: set vim_client_id and vim_client_secret")
	}

	body, err := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     c.clientID,
		"client_secret": c.clientSecret,
		"account_id":    target.AccountID,
	})
	if err != nil {
		return "", err
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, target.url("/app-auth/token"), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return "", fmt.Errorf("mint a Vim access token: %w", err)
	}
	defer func() { _ = httpResponse.Body.Close() }()

	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return "", fmt.Errorf("mint a Vim access token: %w", err)
	}

	if httpResponse.StatusCode != http.StatusOK {
		return "", &StatusError{Operation: "mint a Vim access token", Status: httpResponse.StatusCode, Message: errorMessage(responseBody)}
	}

	var minted struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(responseBody, &minted); err != nil || minted.AccessToken == "" {
		return "", errors.New("mint a Vim access token: Vim answered HTTP 200 with no access_token")
	}

	expiresIn := time.Duration(minted.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 5 * time.Minute
	}
	c.tokens[target] = accessToken{value: minted.AccessToken, expiresAt: time.Now().Add(expiresIn)}

	return minted.AccessToken, nil
}
