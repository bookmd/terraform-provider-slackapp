package slack_test

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflogtest"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack"
	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack/tokens"
)

const installTestBotToken = "xoxb-installtestbottoken"

func installTestServer(t *testing.T) *clientServer {
	t.Helper()

	return newClientServer(t, map[string]string{
		"apps.developerInstall": `{"ok":true,"api_access_tokens":{"bot":"` + installTestBotToken + `"}}`,
		"auth.test":             `{"ok":true,"team_id":"T1","user_id":"U1","bot_id":"B1"}`,
		"bots.info":             `{"ok":true,"bot":{"icons":{"image_72":"https://example.com/72.png"}}}`,
		"apps.icon.set":         `{"ok":true}`,
	})
}

func (s *clientServer) serviceClient(token string) *slack.Client {
	return slack.NewClient().WithServiceToken(tokens.AppConfigurationToken(token)).WithBaseURL(s.URL + "/")
}

func TestClientInstallMethods(t *testing.T) {
	t.Parallel()

	s := installTestServer(t)
	c := s.serviceClient("xoxp-service")
	ctx := t.Context()

	install, err := c.AppsDeveloperInstall(ctx, slack.AppsDeveloperInstallRequest{AppID: "A1"})
	if err != nil {
		t.Fatal(err)
	}
	if string(install.APIAccessTokens.Bot) != installTestBotToken {
		t.Errorf("bot token %q, want %q", string(install.APIAccessTokens.Bot), installTestBotToken)
	}

	identity, err := c.AuthTest(ctx, install.APIAccessTokens.Bot)
	if err != nil {
		t.Fatal(err)
	}
	if identity.TeamID != "T1" || identity.UserID != "U1" || identity.BotID != "B1" {
		t.Errorf("auth.test gave %+v", identity)
	}

	info, err := c.BotsInfo(ctx, slack.BotsInfoRequest{Bot: "B1"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Bot.Icons.Image72 != "https://example.com/72.png" {
		t.Errorf("image_72 %q", info.Bot.Icons.Image72)
	}

	if _, err := c.AppsIconSet(ctx, slack.AppsIconSetRequest{AppID: "A1", FileName: "dir/icon.png", Image: []byte("PNGDATA")}); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"apps.developerInstall(xoxp-service)",
		"auth.test(" + installTestBotToken + ")",
		"bots.info(xoxp-service)",
		"apps.icon.set(xoxp-service)",
	}
	if got := s.methods(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("calls %v, want %v", got, want)
	}

	calls := s.recorded()
	if !clientJSONEqual(t, calls[0].body, `{"app_id":"A1"}`) {
		t.Errorf("apps.developerInstall body %s", calls[0].body)
	}

	form, err := url.ParseQuery(calls[2].body)
	if err != nil || form.Get("bot") != "B1" || calls[2].contentType != "application/x-www-form-urlencoded" {
		t.Errorf("bots.info sent %q as %q", calls[2].body, calls[2].contentType)
	}

	mediaType, params, err := mime.ParseMediaType(calls[3].contentType)
	if err != nil || mediaType != "multipart/form-data" {
		t.Fatalf("apps.icon.set content type %q", calls[3].contentType)
	}
	reader := multipart.NewReader(strings.NewReader(calls[3].body), params["boundary"])
	parts := map[string]string{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(part)
		parts[part.FormName()] = string(data)
		if part.FormName() == "file" && part.FileName() != "icon.png" {
			t.Errorf("file name %q, want icon.png", part.FileName())
		}
	}
	if parts["app_id"] != "A1" || parts["file"] != "PNGDATA" {
		t.Errorf("apps.icon.set parts %v", parts)
	}
}

func TestClientInstallMethodsWithAppConfigurationToken(t *testing.T) {
	t.Parallel()

	s := installTestServer(t)
	c := s.client("xoxe-config")

	if _, err := c.AppsIconSet(t.Context(), slack.AppsIconSetRequest{AppID: "A1", FileName: "i.png", Image: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BotsInfo(t.Context(), slack.BotsInfoRequest{Bot: "B1"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.methods(), " "); got != "apps.icon.set(xoxe-config) bots.info(xoxe-config)" {
		t.Errorf("calls %s", got)
	}
}

// A refused service token cannot be rotated, so the error says how to
// replace it.
func TestClientServiceTokenRefused(t *testing.T) {
	t.Parallel()

	s := installTestServer(t)
	s.refuse("xoxp-revoked", "token_revoked")
	c := s.serviceClient("xoxp-revoked")

	calls := map[string]func() error{
		"apps.developerInstall": func() error {
			_, err := c.AppsDeveloperInstall(t.Context(), slack.AppsDeveloperInstallRequest{AppID: "A1"})

			return err
		},
		"apps.icon.set": func() error {
			_, err := c.AppsIconSet(t.Context(), slack.AppsIconSetRequest{AppID: "A1", FileName: "i.png", Image: []byte("x")})

			return err
		},
	}
	for name, call := range calls {
		err := call()
		if err == nil || !strings.Contains(err.Error(), "token_revoked") || !strings.Contains(err.Error(), "slack auth token") {
			t.Errorf("%s: error %v, want token_revoked and how to replace the token", name, err)
		}
	}

	if n := len(s.recorded()); n != 2 {
		t.Errorf("%d calls, want 2: a refused service token is not retried", n)
	}
}

// Other errors pass through unchanged.
func TestClientServiceTokenOtherError(t *testing.T) {
	t.Parallel()

	s := newClientServer(t, map[string]string{"apps.developerInstall": `{"ok":false,"error":"app_not_found"}`})
	_, err := s.serviceClient("xoxp").AppsDeveloperInstall(t.Context(), slack.AppsDeveloperInstallRequest{AppID: "A1"})
	if err == nil || err.Error() != "app_not_found" {
		t.Errorf("error %v, want app_not_found", err)
	}
}

func TestClientRateLimited(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"ok":false,"error":"ratelimited"}`)

			return
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("PNGDATA")) {
			t.Errorf("the request sent again lacks its body: %q", body)
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(server.Close)

	c := slack.NewClient().WithServiceToken("xoxp").WithBaseURL(server.URL + "/")
	if _, err := c.AppsIconSet(t.Context(), slack.AppsIconSetRequest{AppID: "A1", FileName: "i.png", Image: []byte("PNGDATA")}); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("%d calls, want 3", n)
	}
}

// Without Retry-After the client waits its default, and it gives up after
// a bounded number of calls.
func TestClientRateLimitedGivesUp(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"ok":false,"error":"ratelimited"}`)
	}))
	t.Cleanup(server.Close)

	c := slack.NewClient().WithServiceToken("xoxp").WithBaseURL(server.URL + "/").WithRetryWait(time.Millisecond)
	_, err := c.AppsDeveloperInstall(t.Context(), slack.AppsDeveloperInstallRequest{AppID: "A1"})
	if err == nil || err.Error() != "ratelimited" {
		t.Errorf("error %v, want ratelimited", err)
	}
	if n := calls.Load(); n != 4 {
		t.Errorf("%d calls, want 4", n)
	}
}

func TestClientInstallLogsNoSecrets(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	ctx := tflogtest.RootLogger(t.Context(), &buf)
	s := installTestServer(t)
	c := s.serviceClient("xoxp-servicetokenvalue")

	install, err := c.AppsDeveloperInstall(ctx, slack.AppsDeveloperInstallRequest{AppID: "A1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AuthTest(ctx, install.APIAccessTokens.Bot); err != nil {
		t.Fatal(err)
	}

	for _, secret := range []string{installTestBotToken, "xoxp-servicetokenvalue"} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("the log contains %q", secret)
		}
	}
	if s := install.APIAccessTokens.Bot.String(); s != "[redacted]" {
		t.Errorf("bot token prints as %q", s)
	}
}
