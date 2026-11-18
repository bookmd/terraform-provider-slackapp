package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack"
	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack/tokens"
)

// An abandoned app is deleted even when the apply that abandoned it was
// cancelled, since the app holds live credentials.
func TestVimAppDeleteAbandonedAppOutlivesCancel(t *testing.T) {
	t.Parallel()

	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apps.manifest.delete" && r.Context().Err() == nil {
			deletes.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	r := &vimAppResource{slack: slack.NewClient().WithBaseURL(server.URL + "/").WithServiceToken(tokens.AppConfigurationToken("xoxp-service"))}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var diagnostics diag.Diagnostics
	r.deleteAbandonedApp(ctx, "A1", &diagnostics)

	if diagnostics.HasError() {
		t.Fatalf("diagnostics %v", diagnostics)
	}
	if deletes.Load() != 1 {
		t.Errorf("%d deletes, want 1", deletes.Load())
	}
}
