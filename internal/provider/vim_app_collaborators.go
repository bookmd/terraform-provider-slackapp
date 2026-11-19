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

// vimAppCollaboratorsUnsyncedKey marks, in private state, an apply that did
// not finish setting the collaborators, so that Read never takes the planned
// set as applied.
const vimAppCollaboratorsUnsyncedKey = "collaborators_unsynced"

// vimAppCollaboratorsPrivateState is the private state of a resource, as
// Create, Read and Update each hand it over.
//
//declscope:shared // vim_app.go passes each response's Private
type vimAppCollaboratorsPrivateState interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

//declscope:shared // vim_app.go records each apply's outcome
func vimAppCollaboratorsMarkUnsynced(ctx context.Context, private vimAppCollaboratorsPrivateState, unsynced bool, diagnostics *diag.Diagnostics) {
	value := []byte("false")
	if unsynced {
		value = []byte("true")
	}
	diagnostics.Append(private.SetKey(ctx, vimAppCollaboratorsUnsyncedKey, value)...)
}

//declscope:shared // vim_app.go reads it in Read
func vimAppCollaboratorsUnsynced(ctx context.Context, private vimAppCollaboratorsPrivateState) bool {
	value, _ := private.GetKey(ctx, vimAppCollaboratorsUnsyncedKey)

	return string(value) == "true"
}

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
//declscope:shared // vim_app.go checks it at plan and before changing anything
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

// vimAppCollaboratorsListed is an app's collaborators other than the token's
// own user, sorted.
type vimAppCollaboratorsListed struct {
	owners  []string
	readers []string
}

// vimAppCollaboratorsList lists the app's collaborators. A listing without
// the token's user under the ID auth.test gave is refused: the token could
// not then be told apart from the people to remove.
func (r *vimAppResource) vimAppCollaboratorsList(ctx context.Context, appID, tokenOwner string) (vimAppCollaboratorsListed, error) {
	listed, err := r.slack.DeveloperAppsOwnersList(ctx, slack.DeveloperAppsOwnersListRequest{AppID: appID})
	if err != nil {
		return vimAppCollaboratorsListed{}, err
	}

	var result vimAppCollaboratorsListed
	tokenOwnerListed := false
	for _, owner := range listed.Owners {
		switch {
		case owner.UserID == tokenOwner:
			tokenOwnerListed = true
		case owner.PermissionType == "reader":
			result.readers = append(result.readers, owner.UserID)
		default:
			result.owners = append(result.owners, owner.UserID)
		}
	}
	if !tokenOwnerListed {
		return vimAppCollaboratorsListed{}, fmt.Errorf("slack does not list %s, the service token's user, among the collaborators "+
			"of app %s, so it cannot be told apart from the others; nothing is changed", tokenOwner, appID)
	}
	slices.Sort(result.owners)
	slices.Sort(result.readers)

	return result, nil
}

// vimAppCollaboratorsRead returns the app's collaborators with owner access,
// the token's own user left out.
//
//declscope:shared // vim_app.go reads drift with it
func (r *vimAppResource) vimAppCollaboratorsRead(ctx context.Context, appID, tokenOwner string) ([]string, error) {
	listed, err := r.vimAppCollaboratorsList(ctx, appID, tokenOwner)

	return listed.owners, err
}

// vimAppCollaboratorsApply makes wanted the app's owners besides the token's
// user. It adds before it removes, so the app never has fewer people able to
// manage it than both sets share.
//
//declscope:shared // vim_app.go applies the declared collaborators with it
func (r *vimAppResource) vimAppCollaboratorsApply(ctx context.Context, appID, tokenOwner string, wanted []string) error {
	listed, err := r.vimAppCollaboratorsList(ctx, appID, tokenOwner)
	if err != nil {
		return fmt.Errorf("listing them: %w", err)
	}

	for _, user := range wanted {
		if slices.Contains(listed.owners, user) {
			continue
		}
		// Slack does not say how adding a reader as owner answers, so the
		// reader is removed first.
		if slices.Contains(listed.readers, user) {
			if err := r.vimAppCollaboratorsRemove(ctx, appID, user); err != nil {
				return err
			}
		}
		_, err := r.slack.DeveloperAppsOwnersAdd(ctx, slack.DeveloperAppsOwnersChangeRequest{AppID: appID, UserID: user})
		if err != nil && !slack.IsAlreadyOwnerError(err) {
			return fmt.Errorf("adding %s: %w", user, err)
		}
	}

	for _, user := range slices.Concat(listed.owners, listed.readers) {
		if slices.Contains(wanted, user) {
			continue
		}
		if err := r.vimAppCollaboratorsRemove(ctx, appID, user); err != nil {
			return err
		}
	}

	return nil
}

// vimAppCollaboratorsRemove removes a collaborator who is not the token's
// user; vimAppCollaboratorsList leaves that user out of every set it returns.
func (r *vimAppResource) vimAppCollaboratorsRemove(ctx context.Context, appID, user string) error {
	_, err := r.slack.DeveloperAppsOwnersRemove(ctx, slack.DeveloperAppsOwnersChangeRequest{AppID: appID, UserID: user})
	if err != nil && !slack.IsUserNotFoundError(err) {
		return fmt.Errorf("removing %s: %w", user, err)
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
