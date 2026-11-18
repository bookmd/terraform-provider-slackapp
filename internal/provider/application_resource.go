package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/provider/manifesttype"
	"github.com/ymm-oss/terraform-provider-slackapp/internal/provider/planmodifiers"
	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack"
)

type applicationResourceModel struct {
	// Arguments
	Manifest manifesttype.Manifest `tfsdk:"manifest"`

	// Attributes
	ID                types.String `tfsdk:"id"`
	Credentials       types.Object `tfsdk:"credentials"`
	OauthAuthorizeURL types.String `tfsdk:"oauth_authorize_url"`
}

type applicationResource struct {
	client *slack.Client
}

//declscope:shared // provider.go registers it
func newApplicationResource() resource.Resource {
	return &applicationResource{}
}

func (r *applicationResource) Metadata(
	_ context.Context,
	_ resource.MetadataRequest,
	response *resource.MetadataResponse,
) {
	response.TypeName = "slackapp_application"
}

func (r *applicationResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			// Arguments
			"manifest": &schema.StringAttribute{
				MarkdownDescription: "A JSON app manifest encoded as a string. This manifest must use a valid [app manifest schema - read our guide to creating one](https://api.slack.com/reference/manifests#fields).",
				Required:            true,
				CustomType:          manifesttype.ManifestType{},
				PlanModifiers: []planmodifier.String{
					planmodifiers.SuppressEquivalentManifest(),
				},
			},

			// Attributes
			"id": &schema.StringAttribute{
				MarkdownDescription: "Unique identifier of the app.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"credentials": &schema.ObjectAttribute{
				MarkdownDescription: "Secrets and credentials for the app.",
				Computed:            true,
				Sensitive:           true,
				AttributeTypes: map[string]attr.Type{
					"client_id":          types.StringType,
					"client_secret":      types.StringType,
					"verification_token": types.StringType,
					"signing_secret":     types.StringType,
				},
				PlanModifiers: []planmodifier.Object{
					planmodifiers.KeepPriorObject(),
				},
			},
			"oauth_authorize_url": &schema.StringAttribute{
				MarkdownDescription: "URL of the OAuth 2 authorization endpoint.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					planmodifiers.KeepPriorString(),
				},
			},
		},
	}
}

func (r *applicationResource) Configure(
	_ context.Context,
	request resource.ConfigureRequest,
	response *resource.ConfigureResponse,
) {
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

	r.client = data.slack
}

func (r *applicationResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var data applicationResourceModel

	response.Diagnostics.Append(request.Plan.Get(ctx, &data)...)

	if response.Diagnostics.HasError() {
		return
	}

	apiResponse, err := r.client.AppsManifestCreate(
		ctx, slack.AppsManifestCreateRequest{
			Manifest: data.Manifest.ValueString(),
		},
	)
	if err != nil {
		addSlackError(&response.Diagnostics, "create", err)

		return
	}

	data.ID = types.StringValue(apiResponse.AppID)
	data.Credentials = types.ObjectValueMust(
		map[string]attr.Type{
			"client_id":          types.StringType,
			"client_secret":      types.StringType,
			"verification_token": types.StringType,
			"signing_secret":     types.StringType,
		},
		map[string]attr.Value{
			"client_id":          types.StringValue(apiResponse.Credentials.ClientID),
			"client_secret":      types.StringValue(apiResponse.Credentials.ClientSecret),
			"verification_token": types.StringValue(apiResponse.Credentials.VerificationToken),
			"signing_secret":     types.StringValue(apiResponse.Credentials.SigningSecret),
		},
	)
	data.OauthAuthorizeURL = types.StringValue(apiResponse.OauthAuthorizeURL)

	response.Diagnostics.Append(response.State.Set(ctx, &data)...)
}

func (r *applicationResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var data applicationResourceModel

	response.Diagnostics.Append(request.State.Get(ctx, &data)...)

	if response.Diagnostics.HasError() {
		return
	}

	exported, found := readManifest(ctx, r.client, data.ID.ValueString(), data.Manifest, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}
	if !found {
		// Deleted outside Terraform. Leaving state makes the plan create it
		// again, with a new ID and new credentials.
		response.Diagnostics.AddWarning(
			"The Slack app was not found, so it was removed from state",
			fmt.Sprintf(
				"Slack answered app_not_found for %s, so the plan creates the app again, with a new app ID and new credentials. "+
					"If the app still exists, check that the token is for the workspace that owns it.",
				data.ID.ValueString(),
			),
		)
		response.State.RemoveResource(ctx)

		return
	}

	data.Manifest = exported

	response.Diagnostics.Append(response.State.Set(ctx, &data)...)
}

func (r *applicationResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var before, after applicationResourceModel

	response.Diagnostics.Append(request.State.Get(ctx, &before)...)
	response.Diagnostics.Append(request.Plan.Get(ctx, &after)...)

	if response.Diagnostics.HasError() {
		return
	}

	_, err := r.client.AppsManifestUpdate(
		ctx, slack.AppsManifestUpdateRequest{
			AppID:    after.ID.ValueString(),
			Manifest: after.Manifest.ValueString(),
		},
	)
	if err != nil {
		addSlackError(&response.Diagnostics, "update", err)

		return
	}

	after.Credentials = before.Credentials
	after.OauthAuthorizeURL = before.OauthAuthorizeURL

	response.Diagnostics.Append(response.State.Set(ctx, &after)...)
}

func (r *applicationResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var data applicationResourceModel

	response.Diagnostics.Append(request.State.Get(ctx, &data)...)

	if response.Diagnostics.HasError() {
		return
	}

	_, err := r.client.AppsManifestDelete(
		ctx, slack.AppsManifestDeleteRequest{
			AppID: data.ID.ValueString(),
		},
	)
	if slack.IsAppNotFoundError(err) {
		// Already deleted outside Terraform, which is what destroy wants.
		tflog.Warn(ctx, "The Slack app was already deleted", map[string]any{"app_id": data.ID.ValueString()})

		return
	}
	if err != nil {
		addSlackError(&response.Diagnostics, "delete", err)

		return
	}
}

func (r *applicationResource) ImportState(
	ctx context.Context,
	request resource.ImportStateRequest,
	response *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}
