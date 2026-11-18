package provider

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/manifest"
	"github.com/ymm-oss/terraform-provider-slackapp/internal/provider/manifesttype"
	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack"
)

// readManifest returns the manifest Slack holds for appID, cut down to the
// fields prior has, and whether the app exists.
//
// Slack also answers app_not_found when the token cannot see the app, such
// as a token for another workspace, so the caller warns rather than only
// logging.
//
//declscope:shared
func readManifest(
	ctx context.Context,
	client *slack.Client,
	appID string,
	prior manifesttype.Manifest,
	diagnostics *diag.Diagnostics,
) (manifesttype.Manifest, bool) {
	apiResponse, err := client.AppsManifestExport(ctx, slack.AppsManifestExportRequest{AppID: appID})
	if slack.IsAppNotFoundError(err) {
		tflog.Warn(ctx, "The Slack app no longer exists", map[string]any{"app_id": appID})

		return manifesttype.Manifest{}, false
	}
	if err != nil {
		addSlackError(diagnostics, "read", err)

		return manifesttype.Manifest{}, true
	}

	if len(apiResponse.Manifest) == 0 || string(apiResponse.Manifest) == "null" {
		diagnostics.AddError("Slack API returned empty manifest.", "apps.manifest.export returned ok but no manifest payload")

		return manifesttype.Manifest{}, true
	}

	var exported map[string]json.RawMessage
	if err := json.Unmarshal(apiResponse.Manifest, &exported); err != nil {
		diagnostics.AddError("Slack API returned a manifest that is not a JSON object.", err.Error())

		return manifesttype.Manifest{}, true
	}

	// Slack drops _metadata from the manifest on applying, so carry it over
	// from the manifest in state. On import there is none yet.
	hasLocalManifest := !prior.IsNull() && !prior.IsUnknown() && strings.TrimSpace(prior.ValueString()) != ""
	if _, ok := exported["_metadata"]; !ok && hasLocalManifest {
		var local map[string]json.RawMessage
		if err := json.Unmarshal([]byte(prior.ValueString()), &local); err != nil {
			diagnostics.AddAttributeError(path.Root("manifest"), "Manifest must be a valid JSON.", err.Error())

			return manifesttype.Manifest{}, true
		}

		if metadata, ok := local["_metadata"]; ok {
			exported["_metadata"] = metadata
		}
	}

	// Every field Slack exported is kept, including the ones
	// the slackapp_manifest data source does not model.
	manifestJSON, err := json.Marshal(exported)
	if err != nil {
		diagnostics.AddError("Failed to re-serialize the JSON manifest.", err.Error())

		return manifesttype.Manifest{}, true
	}

	// Slack fills in every setting the manifest did not state. Keep only the
	// fields the manifest in state has, so those defaults do not show as
	// drift. On import there is no manifest in state, and all of it is kept.
	if hasLocalManifest {
		pruned, err := manifest.PruneToPrior(string(manifestJSON), prior.ValueString())
		if err != nil {
			diagnostics.AddError("Failed to compare the exported manifest with the one in state.", err.Error())

			return manifesttype.Manifest{}, true
		}

		manifestJSON = []byte(pruned)
	}

	return manifesttype.NewManifestValue(string(manifestJSON)), true
}
