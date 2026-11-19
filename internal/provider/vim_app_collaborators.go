package provider

import (
	"context"
	"fmt"
	"regexp"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack"
)

//declscope:shared // vim_app.go validates the schema's elements with it
var vimAppCollaboratorsUserIDPattern = regexp.MustCompile(`^[UW][A-Z0-9]{2,}$`)

// vimAppCollaboratorsWanted returns the declared collaborators, sorted, and
// whether they are declared at all.
//
//declscope:shared // vim_app.go decides from it whether to manage collaborators
func vimAppCollaboratorsWanted(ctx context.Context, set types.Set, diagnostics *diag.Diagnostics) ([]string, bool) {
	if set.IsNull() || set.IsUnknown() {
		return nil, false
	}

	wanted := []string{}
	diagnostics.Append(set.ElementsAs(ctx, &wanted, false)...)
	slices.Sort(wanted)

	return wanted, true
}

// vimAppCollaboratorsTokenOwner returns the user the service token acts
// as. That user created the app and stays its owner, so it cannot be
// declared: Read leaves it out, and removing it would leave nobody able to
// manage the app through the token.
//
//declscope:shared // vim_app.go checks it before changing anything
func (r *vimAppResource) vimAppCollaboratorsTokenOwner(ctx context.Context, wanted []string, diagnostics *diag.Diagnostics) (string, bool) {
	caller, err := r.slack.AuthTestCaller(ctx)
	if err != nil {
		diagnostics.AddError("Failed to identify the service token's user", err.Error())

		return "", false
	}

	if slices.Contains(wanted, caller.UserID) {
		diagnostics.AddError("A collaborator is the service token's user",
			fmt.Sprintf("%s is the user the service token acts as. It owns every app the provider creates, "+
				"so it is not a collaborator to declare. Remove it from collaborators.", caller.UserID))

		return "", false
	}

	return caller.UserID, true
}

// vimAppCollaboratorsRead lists the app's collaborators other than the
// token's own user, sorted.
//
//declscope:shared // vim_app.go reads drift with it
func (r *vimAppResource) vimAppCollaboratorsRead(ctx context.Context, appID, tokenOwner string) ([]string, error) {
	listed, err := r.slack.DeveloperAppsOwnersList(ctx, slack.DeveloperAppsOwnersListRequest{AppID: appID})
	if err != nil {
		return nil, err
	}

	collaborators := []string{}
	for _, owner := range listed.Owners {
		if owner.UserID != tokenOwner {
			collaborators = append(collaborators, owner.UserID)
		}
	}
	slices.Sort(collaborators)

	return collaborators, nil
}

// vimAppCollaboratorsApply adds the wanted collaborators the app lacks, then
// removes the ones not wanted. Adding first never leaves the app with fewer
// people able to manage it.
//
//declscope:shared // vim_app.go applies the declared collaborators with it
func (r *vimAppResource) vimAppCollaboratorsApply(ctx context.Context, appID, tokenOwner string, wanted []string) error {
	current, err := r.vimAppCollaboratorsRead(ctx, appID, tokenOwner)
	if err != nil {
		return fmt.Errorf("listing them: %w", err)
	}

	for _, user := range wanted {
		if slices.Contains(current, user) {
			continue
		}
		_, err := r.slack.DeveloperAppsOwnersAdd(ctx, slack.DeveloperAppsOwnersChangeRequest{AppID: appID, UserID: user})
		if err != nil && !slack.IsAlreadyOwnerError(err) {
			return fmt.Errorf("adding %s: %w", user, err)
		}
	}

	for _, user := range current {
		if slices.Contains(wanted, user) {
			continue
		}
		if _, err := r.slack.DeveloperAppsOwnersRemove(ctx, slack.DeveloperAppsOwnersChangeRequest{AppID: appID, UserID: user}); err != nil {
			return fmt.Errorf("removing %s: %w", user, err)
		}
	}

	return nil
}

// vimAppCollaboratorsSet is the set attribute holding collaborators.
//
//declscope:shared // vim_app.go records what Read found with it
func vimAppCollaboratorsSet(collaborators []string) types.Set {
	elements := make([]attr.Value, len(collaborators))
	for i, c := range collaborators {
		elements[i] = types.StringValue(c)
	}

	return types.SetValueMust(types.StringType, elements)
}
