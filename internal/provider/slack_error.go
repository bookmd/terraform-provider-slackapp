package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack"
)

// addSlackError adds err to diagnostics. operation is the verb for what
// failed, such as "create" or "install".
//
// When Slack lists what is wrong, each item is its own error under the
// message Slack gave, and the detail names the operation and where in the
// manifest the item points. Otherwise the summary names the operation.
//
//declscope:shared
func addSlackError(diagnostics *diag.Diagnostics, operation string, err error) {
	summary := "Failed to " + operation + " the Slack app"

	slackErr, ok := err.(*slack.ErrorResponse)
	if ok && len(slackErr.Errors) > 0 {
		for _, e := range slackErr.Errors {
			detail := summary + "."
			if e.Pointer != "" {
				detail += " Slack points to " + e.Pointer + " in the manifest."
			}

			diagnostics.AddError(e.Message, detail)
		}
	} else {
		diagnostics.AddError(summary, err.Error())
	}
}
