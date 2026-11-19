package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/provider/manifesttype"
	"github.com/ymm-oss/terraform-provider-slackapp/internal/provider/planmodifiers"
	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack"
	"github.com/ymm-oss/terraform-provider-slackapp/internal/vault"
)

// The fields of the vault secret. Its consumers read them by these names.
const (
	vimAppBotTokenField      = "botToken"
	vimAppSigningSecretField = "signingSecret"
	vimAppSecretAuthKind     = "custom"
	// vimAppDeleteTimeout bounds deleting an abandoned app, which runs even
	// when the apply is cancelled.
	vimAppDeleteTimeout = 30 * time.Second
)

// vimAppBaseURLPattern admits https with no user info, and http only on the
// loopback host: the platform app's client secret is sent to this URL.
var vimAppBaseURLPattern = regexp.MustCompile(`^(https://[^/?#@\s]+|http://(localhost|127\.0\.0\.1)(:[0-9]+)?)(/[^@\s]*)?$`)

type vimAppResourceModel struct {
	Manifest        manifesttype.Manifest `tfsdk:"manifest"`
	IconPath        types.String          `tfsdk:"icon_path"`
	VimBaseURL      types.String          `tfsdk:"vim_base_url"`
	VimAccountID    types.String          `tfsdk:"vim_account_id"`
	VaultSecretName types.String          `tfsdk:"vault_secret_name"`
	VaultConsumers  types.Set             `tfsdk:"vault_consumers"`
	Collaborators   types.Set             `tfsdk:"collaborators"`

	ID               types.String `tfsdk:"id"`
	TeamID           types.String `tfsdk:"team_id"`
	BotUserID        types.String `tfsdk:"bot_user_id"`
	BotID            types.String `tfsdk:"bot_id"`
	VaultSecretToken types.String `tfsdk:"vault_secret_token"`
	BotTokenRef      types.String `tfsdk:"bot_token_ref"`
	SigningSecretRef types.String `tfsdk:"signing_secret_ref"`
	BotTokenSHA256   types.String `tfsdk:"bot_token_sha256"`
	IconSHA256       types.String `tfsdk:"icon_sha256"`
	IconImageURL     types.String `tfsdk:"icon_image_url"`
}

func (m vimAppResourceModel) target() vault.Target {
	return vault.Target{BaseURL: m.VimBaseURL.ValueString(), AccountID: m.VimAccountID.ValueString()}
}

func (m vimAppResourceModel) consumers(ctx context.Context, diagnostics *diag.Diagnostics) []string {
	consumers := []string{}
	diagnostics.Append(m.VaultConsumers.ElementsAs(ctx, &consumers, false)...)
	slices.Sort(consumers)

	return consumers
}

//declscope:shared // vim_app_delete_test.go deletes an abandoned app directly
type vimAppResource struct {
	slack *slack.Client
	//declscope:private
	vault *vault.Client
}

var _ resource.ResourceWithModifyPlan = &vimAppResource{}

//declscope:shared
func newVimAppResource() resource.Resource {
	return &vimAppResource{}
}

func (r *vimAppResource) Metadata(_ context.Context, _ resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = "slackapp_vim_app"
}

func (r *vimAppResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}

	response.Schema = schema.Schema{
		MarkdownDescription: "A Slack app, installed in the workspace of the provider's `service_token`, whose bot token and " +
			"signing secret are written to a named secret in a Vim account's vault and nowhere else: not to state and not to the plan. " +
			"State keeps the secret's `vscrt_` token and a hash of the bot token.\n\n" +
			"Destroy deletes the app but not the vault secret, since the Vim platform app may not delete one. " +
			"Creating the app again under the same `vault_secret_name` fails until the secret is deleted in Vim.",
		Attributes: map[string]schema.Attribute{
			"manifest": schema.StringAttribute{
				MarkdownDescription: "A JSON app manifest encoded as a string. It has no icon: set `icon_path`. " +
					"A change that adds bot scopes installs the app again.",
				Required:      true,
				CustomType:    manifesttype.ManifestType{},
				PlanModifiers: []planmodifier.String{planmodifiers.SuppressEquivalentManifest()},
			},
			"icon_path": schema.StringAttribute{
				MarkdownDescription: "Path of the app icon: a PNG, JPEG or GIF of 512 to 2000 pixels per side. " +
					"It is set when its contents change, judged by `icon_sha256`.",
				Optional: true,
			},
			"vim_base_url": schema.StringAttribute{
				MarkdownDescription: "Base URL of the Vim backend whose vault holds the secret, such as `https://api.getvim.ai`. " +
					"It is https, or http on `localhost` or `127.0.0.1`.",
				Required:      true,
				PlanModifiers: replace,
				Validators: []validator.String{stringvalidator.RegexMatches(vimAppBaseURLPattern,
					"must be https:// with no user info, or http:// on localhost or 127.0.0.1")},
			},
			"vim_account_id": schema.StringAttribute{
				MarkdownDescription: "The Vim account whose vault holds the secret.",
				Required:            true,
				PlanModifiers:       replace,
			},
			"vault_secret_name": schema.StringAttribute{
				MarkdownDescription: "Name of the vault secret. It must be unique in the account.",
				Required:            true,
				PlanModifiers:       replace,
			},
			"vault_consumers": schema.SetAttribute{
				MarkdownDescription: "The services that may reveal the secret, each `<service>:<name>`.",
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				Default:             setdefault.StaticValue(types.SetValueMust(types.StringType, nil)),
			},
			"collaborators": schema.SetAttribute{
				MarkdownDescription: "Slack user IDs, such as `U0123ABCD`, of the people who may manage the app at " +
					"https://api.slack.com/apps, beside the service token's user, who owns it and is never listed. " +
					"Each is added as an owner, and a collaborator not listed is removed, including one added in Slack. " +
					"Unset, the provider leaves the collaborators as they are.",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{setvalidator.ValueStringsAre(stringvalidator.RegexMatches(
					vimAppCollaboratorsUserIDPattern, "must be a Slack user ID, such as U0123ABCD"))},
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "The app ID.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"team_id": schema.StringAttribute{
				MarkdownDescription: "The workspace the app is installed in.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"bot_user_id": schema.StringAttribute{
				MarkdownDescription: "The app's bot user.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"bot_id": schema.StringAttribute{
				MarkdownDescription: "The app's bot.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"vault_secret_token": schema.StringAttribute{
				MarkdownDescription: "The vault secret's `vscrt_` token.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"bot_token_ref": schema.StringAttribute{
				MarkdownDescription: "Reference to the bot token in the vault: `vscrt_<token>@botToken`.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"signing_secret_ref": schema.StringAttribute{
				MarkdownDescription: "Reference to the signing secret in the vault: `vscrt_<token>@signingSecret`.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"bot_token_sha256": schema.StringAttribute{
				MarkdownDescription: "SHA-256 of the bot token in the vault.",
				Computed:            true,
				PlanModifiers:       keep,
			},
			"icon_sha256": schema.StringAttribute{
				MarkdownDescription: "SHA-256 of the icon last set. Null when no icon is set, or when the icon was changed in Slack.",
				Computed:            true,
			},
			"icon_image_url": schema.StringAttribute{
				MarkdownDescription: "The URL Slack serves the icon at. A new URL means the icon changed.",
				Computed:            true,
			},
		},
	}
}

func (r *vimAppResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if request.ProviderData == nil {
		return
	}

	data, ok := request.ProviderData.(*providerData)
	if !ok {
		response.Diagnostics.AddError(
			"The provider is not configured properly.",
			fmt.Sprintf("request.ProviderData is %T, not *providerData", request.ProviderData),
		)

		return
	}

	r.slack = data.slack
	r.vault = data.vault
}

func (r *vimAppResource) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	if request.Plan.Raw.IsNull() {
		var state vimAppResourceModel
		response.Diagnostics.Append(request.State.Get(ctx, &state)...)
		response.Diagnostics.AddWarning(
			"The vault secret is not deleted",
			fmt.Sprintf("Destroy deletes Slack app %s, but not vault secret %q (%s): the Vim platform app may not delete a secret. "+
				"Delete it in Vim before creating an app with that secret name again.",
				state.ID.ValueString(), state.VaultSecretName.ValueString(), state.VaultSecretToken.ValueString()),
		)

		return
	}

	var plan, state vimAppResourceModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if !request.State.Raw.IsNull() {
		response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	}
	if response.Diagnostics.HasError() {
		return
	}

	creating := request.State.Raw.IsNull()
	appGone := !creating && state.ID.IsNull()

	switch {
	case plan.IconPath.IsUnknown():
		plan.IconSHA256 = types.StringUnknown()
		plan.IconImageURL = types.StringUnknown()
	case plan.IconPath.IsNull():
		plan.IconSHA256 = state.IconSHA256
		plan.IconImageURL = state.IconImageURL
	default:
		icon, err := readIcon(plan.IconPath.ValueString())
		if err != nil {
			response.Diagnostics.AddAttributeError(path.Root("icon_path"), "Slack does not take this app icon", err.Error())

			return
		}

		// Unknown, not the new hash: a failed set leaves it null.
		plan.IconSHA256 = state.IconSHA256
		plan.IconImageURL = state.IconImageURL
		if creating || appGone || state.IconSHA256.ValueString() != icon.sha256 {
			plan.IconSHA256 = types.StringUnknown()
			plan.IconImageURL = types.StringUnknown()
		}
	}

	if appGone {
		plan.ID = types.StringUnknown()
		plan.TeamID = types.StringUnknown()
		plan.BotUserID = types.StringUnknown()
		plan.BotID = types.StringUnknown()
		plan.BotTokenSHA256 = types.StringUnknown()
	}

	response.Diagnostics.Append(response.Plan.Set(ctx, &plan)...)
}

// vimAppInstalled is what creating and installing an app returns. The bot token
// and signing secret live only here, on their way to the vault.
type vimAppInstalled struct {
	appID         string
	signingSecret string
	botToken      slack.BotToken
	identity      *slack.AuthTestResponse
}

func (i vimAppInstalled) fields() vault.Fields {
	return vault.Fields{
		vimAppBotTokenField:      string(i.botToken),
		vimAppSigningSecretField: i.signingSecret,
	}
}

func (i vimAppInstalled) apply(data *vimAppResourceModel) {
	data.ID = types.StringValue(i.appID)
	data.TeamID = types.StringValue(i.identity.TeamID)
	data.BotUserID = types.StringValue(i.identity.UserID)
	data.BotID = types.StringValue(i.identity.BotID)
	data.BotTokenSHA256 = types.StringValue(vimAppBotTokenSHA256(i.botToken))
}

// vimAppBotScopes returns the manifest's bot scopes, sorted. A manifest that
// cannot be read has none: Slack itself refuses it.
func vimAppBotScopes(m manifesttype.Manifest) []string {
	var parsed struct {
		OauthConfig struct {
			Scopes struct {
				Bot []string `json:"bot"`
			} `json:"scopes"`
		} `json:"oauth_config"`
	}
	_ = json.Unmarshal([]byte(m.ValueString()), &parsed)
	scopes := slices.Clone(parsed.OauthConfig.Scopes.Bot)
	slices.Sort(scopes)

	return scopes
}

func vimAppBotTokenSHA256(token slack.BotToken) string {
	sum := sha256.Sum256([]byte(token))

	return hex.EncodeToString(sum[:])
}

// createAndInstall creates the app and installs it. When install fails, it
// deletes the app: Slack returns the signing secret on create only, so an
// app whose secret is not on its way to the vault is of no use.
func (r *vimAppResource) createAndInstall(ctx context.Context, manifest string, diagnostics *diag.Diagnostics) (vimAppInstalled, bool) {
	created, err := r.slack.AppsManifestCreate(ctx, slack.AppsManifestCreateRequest{Manifest: manifest})
	if err != nil {
		addSlackError(diagnostics, "create", err)

		return vimAppInstalled{}, false
	}

	result := vimAppInstalled{appID: created.AppID, signingSecret: created.Credentials.SigningSecret}

	install, err := r.slack.AppsDeveloperInstall(ctx, slack.AppsDeveloperInstallRequest{AppID: created.AppID})
	if err != nil {
		addSlackError(diagnostics, "install", err)
		r.deleteAbandonedApp(ctx, created.AppID, diagnostics)

		return vimAppInstalled{}, false
	}
	result.botToken = install.APIAccessTokens.Bot

	if result.identity, err = r.slack.AuthTest(ctx, result.botToken); err != nil {
		addSlackError(diagnostics, "identify the bot of", err)
		r.deleteAbandonedApp(ctx, created.AppID, diagnostics)

		return vimAppInstalled{}, false
	}

	return result, true
}

// deleteAbandonedApp deletes an app whose credentials did not reach the
// vault, so that the next apply creates it again from the start.
//
// It runs on its own deadline, past a cancelled apply, since the app holds
// live credentials.
//
//declscope:shared // vim_app_delete_test.go cancels the context first
func (r *vimAppResource) deleteAbandonedApp(ctx context.Context, appID string, diagnostics *diag.Diagnostics) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), vimAppDeleteTimeout)
	defer cancel()

	_, err := r.slack.AppsManifestDelete(ctx, slack.AppsManifestDeleteRequest{AppID: appID})
	if err == nil || slack.IsAppNotFoundError(err) {
		tflog.Warn(ctx, "Deleted the Slack app, whose credentials did not reach the vault", map[string]any{"app_id": appID})

		return
	}

	diagnostics.AddError(
		"Failed to delete the Slack app after its credentials did not reach the vault",
		fmt.Sprintf("Delete app %s by hand at https://api.slack.com/apps, since its signing secret is lost: %s", appID, err),
	)
}

// setIcon sets the planned icon, and records the URL Slack serves it at.
// A failure leaves icon_sha256 null, so that the next plan sets it again.
func (r *vimAppResource) setIcon(ctx context.Context, data *vimAppResourceModel, diagnostics *diag.Diagnostics) {
	if data.IconPath.IsNull() {
		return
	}

	icon, err := readIcon(data.IconPath.ValueString())
	if err == nil {
		_, err = r.slack.AppsIconSet(ctx, slack.AppsIconSetRequest{AppID: data.ID.ValueString(), FileName: icon.path, Image: icon.image})
	}
	if err != nil {
		data.IconSHA256 = types.StringNull()
		data.IconImageURL = types.StringNull()
		diagnostics.AddWarning("Failed to set the Slack app icon", "The next plan sets it again: "+err.Error())

		return
	}

	data.IconSHA256 = types.StringValue(icon.sha256)
	data.IconImageURL = types.StringNull()

	info, err := r.slack.BotsInfo(ctx, slack.BotsInfoRequest{Bot: data.BotID.ValueString()})
	if err != nil {
		diagnostics.AddWarning("Failed to read the Slack app icon back", "A later change to the icon in Slack is not detected: "+err.Error())

		return
	}

	data.IconImageURL = types.StringValue(info.Bot.Icons.Image72)
}

func (r *vimAppResource) recordSecret(data *vimAppResourceModel, secret *vault.Secret, diagnostics *diag.Diagnostics) bool {
	for _, field := range []string{vimAppBotTokenField, vimAppSigningSecretField} {
		if !slices.Contains(secret.Fields, field) {
			diagnostics.AddError("The vault secret lacks a field",
				fmt.Sprintf("Vim reports fields %v for secret %s, without %q.", secret.Fields, secret.Token, field))

			return false
		}
	}

	data.VaultSecretToken = types.StringValue(secret.Token)
	data.BotTokenRef = types.StringValue(secret.Token + "@" + vimAppBotTokenField)
	data.SigningSecretRef = types.StringValue(secret.Token + "@" + vimAppSigningSecretField)

	return true
}

func (r *vimAppResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var data vimAppResourceModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &data)...)
	consumers := data.consumers(ctx, &response.Diagnostics)
	collaborators, managed := vimAppCollaboratorsWanted(ctx, data.Collaborators, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}

	var tokenOwner string
	if managed {
		if tokenOwner, managed = r.vimAppCollaboratorsTokenOwner(ctx, collaborators, &response.Diagnostics); !managed {
			return
		}
	}

	app, ok := r.createAndInstall(ctx, data.Manifest.ValueString(), &response.Diagnostics)
	if !ok {
		return
	}

	secret, err := r.vault.CreateSecret(ctx, data.target(), vault.CreateSecretRequest{
		Name:      data.VaultSecretName.ValueString(),
		AuthKind:  vimAppSecretAuthKind,
		Fields:    app.fields(),
		Consumers: consumers,
	})
	if err != nil {
		name := data.VaultSecretName.ValueString()
		if vault.IsConflictAfterRetry(err) {
			response.Diagnostics.AddError("The vault secret may hold this Slack app's credentials",
				fmt.Sprintf("Vim answered 409 to a repeated create of secret %q, so an earlier attempt may have written it "+
					"with the credentials of app %s. The app is kept. Either delete the secret in Vim and app %s at "+
					"https://api.slack.com/apps, then apply again; or keep both and adopt them by hand. (%s)",
					name, app.appID, app.appID, err))

			return
		}

		detail := err.Error()
		if vault.IsConflict(err) {
			detail = fmt.Sprintf("The Vim account already has a secret named %q. Delete it in Vim, then apply again. (%s)", name, err)
		}
		response.Diagnostics.AddError("Failed to write the Slack app's credentials to the vault", detail)
		r.deleteAbandonedApp(ctx, app.appID, &response.Diagnostics)

		return
	}

	if !r.recordSecret(&data, secret, &response.Diagnostics) {
		r.deleteAbandonedApp(ctx, app.appID, &response.Diagnostics)

		return
	}

	app.apply(&data)
	r.setIcon(ctx, &data, &response.Diagnostics)

	if managed {
		// A warning, not an error: an error would taint the app, and replacing
		// it fails on the vault secret it leaves. The next Read shows the gap.
		if err := r.vimAppCollaboratorsApply(ctx, data.ID.ValueString(), tokenOwner, collaborators); err != nil {
			response.Diagnostics.AddWarning("Failed to set the Slack app's collaborators", "The next plan sets them again: "+err.Error())
		}
	}

	response.Diagnostics.Append(response.State.Set(ctx, &data)...)
}

func (r *vimAppResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var data vimAppResourceModel
	response.Diagnostics.Append(request.State.Get(ctx, &data)...)
	if response.Diagnostics.HasError() || data.ID.IsNull() {
		return
	}

	exported, found := readManifest(ctx, r.slack, data.ID.ValueString(), data.Manifest, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}

	if !found {
		// The vault secret outlives the app, so the plan creates the app
		// again in place and writes its new credentials to the same secret.
		response.Diagnostics.AddWarning(
			"The Slack app was not found",
			fmt.Sprintf("Slack answered app_not_found for %s, so the plan creates the app again, with a new app ID, "+
				"and writes its credentials to vault secret %s. "+
				"If the app still exists, check that the service token is for the workspace that owns it.",
				data.ID.ValueString(), data.VaultSecretToken.ValueString()),
		)
		data.ID = types.StringNull()
		response.Diagnostics.Append(response.State.Set(ctx, &data)...)

		return
	}

	data.Manifest = exported
	r.readCollaborators(ctx, &data, &response.Diagnostics)

	if !data.IconImageURL.IsNull() && !data.BotID.IsNull() {
		info, err := r.slack.BotsInfo(ctx, slack.BotsInfoRequest{Bot: data.BotID.ValueString()})
		switch {
		case err != nil:
			tflog.Warn(ctx, "Failed to read the Slack app icon", map[string]any{"error": err.Error()})
		case info.Bot.Icons.Image72 != data.IconImageURL.ValueString():
			// Changed in Slack: the plan sets the icon again.
			data.IconSHA256 = types.StringNull()
			data.IconImageURL = types.StringValue(info.Bot.Icons.Image72)
		}
	}

	response.Diagnostics.Append(response.State.Set(ctx, &data)...)
}

// readCollaborators records the app's collaborators, when they are declared,
// so that one added or removed in Slack shows as drift.
func (r *vimAppResource) readCollaborators(ctx context.Context, data *vimAppResourceModel, diagnostics *diag.Diagnostics) {
	if data.Collaborators.IsNull() {
		return
	}

	caller, err := r.slack.AuthTestCaller(ctx)
	var collaborators []string
	if err == nil {
		collaborators, err = r.vimAppCollaboratorsRead(ctx, data.ID.ValueString(), caller.UserID)
	}
	if err != nil {
		diagnostics.AddWarning("Failed to read the Slack app's collaborators",
			"A change to them in Slack is not detected: "+err.Error())

		return
	}

	data.Collaborators = vimAppCollaboratorsSet(collaborators)
}

func (r *vimAppResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var state, plan vimAppResourceModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	collaborators, managed := vimAppCollaboratorsWanted(ctx, plan.Collaborators, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}

	recreating := state.ID.IsNull()
	var tokenOwner string
	if managed && (recreating || !plan.Collaborators.Equal(state.Collaborators)) {
		if tokenOwner, managed = r.vimAppCollaboratorsTokenOwner(ctx, collaborators, &response.Diagnostics); !managed {
			response.Diagnostics.Append(response.State.Set(ctx, &state)...)

			return
		}
	} else {
		managed = false
	}

	if recreating {
		r.recreate(ctx, &plan, state.TeamID.ValueString(), &response.Diagnostics)
	} else {
		r.updateInPlace(ctx, state, &plan, &response.Diagnostics)
	}
	if response.Diagnostics.HasError() {
		// What failed is planned again from the state as it was.
		response.Diagnostics.Append(response.State.Set(ctx, &state)...)

		return
	}

	if !plan.VaultConsumers.Equal(state.VaultConsumers) {
		consumers := plan.consumers(ctx, &response.Diagnostics)
		if _, err := r.vault.SetConsumers(ctx, plan.target(), plan.VaultSecretToken.ValueString(), consumers); err != nil {
			response.Diagnostics.AddError("Failed to set the services the vault secret is shared with", err.Error())
			plan.VaultConsumers = state.VaultConsumers
		}
	}

	if managed {
		if err := r.vimAppCollaboratorsApply(ctx, plan.ID.ValueString(), tokenOwner, collaborators); err != nil {
			// The next Read records which changes took effect.
			response.Diagnostics.AddError("Failed to set the Slack app's collaborators", err.Error())
		}
	}

	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

// recreate creates again an app deleted in Slack, in the workspace that
// held it, and writes its new credentials to the secret the old one used, so
// its consumers follow.
func (r *vimAppResource) recreate(ctx context.Context, plan *vimAppResourceModel, teamID string, diagnostics *diag.Diagnostics) {
	app, ok := r.createAndInstall(ctx, plan.Manifest.ValueString(), diagnostics)
	if !ok {
		return
	}

	if app.identity.TeamID != teamID {
		diagnostics.AddError("The Slack app would move to another workspace",
			fmt.Sprintf("The app being replaced was in workspace %s, but the service token created the new one in %s. "+
				"Vault secret %s is left as it is. Use a service token for workspace %s; "+
				"if the app it held still exists there, it is not gone.",
				teamID, app.identity.TeamID, plan.VaultSecretToken.ValueString(), teamID))
		r.deleteAbandonedApp(ctx, app.appID, diagnostics)

		return
	}

	secret, err := r.vault.RotateSecret(ctx, plan.target(), plan.VaultSecretToken.ValueString(),
		vault.RotateSecretRequest{AuthKind: vimAppSecretAuthKind, Fields: app.fields()})
	if err != nil {
		diagnostics.AddError("Failed to write the new Slack app's credentials to the vault", err.Error())
		r.deleteAbandonedApp(ctx, app.appID, diagnostics)

		return
	}

	if !r.recordSecret(plan, secret, diagnostics) {
		r.deleteAbandonedApp(ctx, app.appID, diagnostics)

		return
	}

	app.apply(plan)
	r.setIcon(ctx, plan, diagnostics)
}

func (r *vimAppResource) updateInPlace(ctx context.Context, state vimAppResourceModel, plan *vimAppResourceModel, diagnostics *diag.Diagnostics) {
	if !plan.Manifest.Equal(state.Manifest) {
		updated, err := r.slack.AppsManifestUpdate(ctx, slack.AppsManifestUpdateRequest{
			AppID:    plan.ID.ValueString(),
			Manifest: plan.Manifest.ValueString(),
		})
		if err != nil {
			addSlackError(diagnostics, "update", err)

			return
		}

		if updated.PermissionsUpdated || !slices.Equal(vimAppBotScopes(plan.Manifest), vimAppBotScopes(state.Manifest)) {
			r.reinstall(ctx, plan, diagnostics)
			if diagnostics.HasError() {
				return
			}
		}
	}

	if plan.IconSHA256.IsUnknown() {
		r.setIcon(ctx, plan, diagnostics)
	}
}

// reinstall installs the app again so its bot holds the scopes the manifest
// added. Slack keeps the bot token, so the vault secret stays as it is.
func (r *vimAppResource) reinstall(ctx context.Context, plan *vimAppResourceModel, diagnostics *diag.Diagnostics) {
	install, err := r.slack.AppsDeveloperInstall(ctx, slack.AppsDeveloperInstallRequest{AppID: plan.ID.ValueString()})
	if err != nil {
		addSlackError(diagnostics, "install", err)

		return
	}

	if vimAppBotTokenSHA256(install.APIAccessTokens.Bot) != plan.BotTokenSHA256.ValueString() {
		diagnostics.AddError(
			"Installing the Slack app again changed its bot token",
			fmt.Sprintf("The vault secret %s still holds the old bot token, and the signing secret it also holds cannot be read back "+
				"to write both again. Replace the resource to create the app and its secret anew.", plan.VaultSecretToken.ValueString()),
		)
	}
}

func (r *vimAppResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var data vimAppResourceModel
	response.Diagnostics.Append(request.State.Get(ctx, &data)...)
	if response.Diagnostics.HasError() || data.ID.IsNull() {
		return
	}

	_, err := r.slack.AppsManifestDelete(ctx, slack.AppsManifestDeleteRequest{AppID: data.ID.ValueString()})
	if err != nil && !slack.IsAppNotFoundError(err) {
		addSlackError(&response.Diagnostics, "delete", err)
	}
}
