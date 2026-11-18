//declscope:core // the slack package's API: Slack Web API methods and the types they share

package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/ymm-oss/terraform-provider-slackapp/internal/slack/tokens"
)

type AppsManifestCreateRequest struct {
	Manifest string `json:"manifest"`
}

type AppsManifestCreateResponse struct {
	Ok          bool   `json:"ok"`
	AppID       string `json:"app_id"`
	Credentials struct {
		ClientID          string `json:"client_id"`
		ClientSecret      string `json:"client_secret"`
		VerificationToken string `json:"verification_token"`
		SigningSecret     string `json:"signing_secret"`
	} `json:"credentials"`
	OauthAuthorizeURL string `json:"oauth_authorize_url"`
}

func (r AppsManifestCreateResponse) IsOk() bool {
	return r.Ok
}

// logFields leaves out Credentials: they are the app's secrets.
func (r AppsManifestCreateResponse) logFields() map[string]any {
	return map[string]any{"app_id": r.AppID}
}

func (c *Client) AppsManifestCreate(
	ctx context.Context,
	request AppsManifestCreateRequest,
) (*AppsManifestCreateResponse, error) {
	return callMethod[AppsManifestCreateResponse](ctx, c, "apps.manifest.create", &request)
}

type AppsManifestUpdateRequest struct {
	AppID    string `json:"app_id"`
	Manifest string `json:"manifest"`
}

type AppsManifestUpdateResponse struct {
	Ok                 bool   `json:"ok"`
	AppID              string `json:"app_id"`
	PermissionsUpdated bool   `json:"permissions_updated"`
}

func (r AppsManifestUpdateResponse) IsOk() bool {
	return r.Ok
}

func (r AppsManifestUpdateResponse) logFields() map[string]any {
	return map[string]any{"app_id": r.AppID, "permissions_updated": r.PermissionsUpdated}
}

func (c *Client) AppsManifestUpdate(
	ctx context.Context,
	request AppsManifestUpdateRequest,
) (*AppsManifestUpdateResponse, error) {
	return callMethod[AppsManifestUpdateResponse](ctx, c, "apps.manifest.update", &request)
}

type AppsManifestExportRequest struct {
	AppID string `json:"app_id"`
}

type AppsManifestExportResponse struct {
	Ok bool `json:"ok"`
	// Manifest is kept as the raw JSON Slack returned. Decoding it into
	// a struct would drop every field that struct does not model.
	Manifest json.RawMessage `json:"manifest"`
}

func (r AppsManifestExportResponse) IsOk() bool {
	return r.Ok
}

func (r AppsManifestExportResponse) logFields() map[string]any {
	return nil
}

func (c *Client) AppsManifestExport(
	ctx context.Context,
	request AppsManifestExportRequest,
) (*AppsManifestExportResponse, error) {
	return callMethod[AppsManifestExportResponse](ctx, c, "apps.manifest.export", &request)
}

type AppsManifestDeleteRequest struct {
	AppID string `json:"app_id"`
}

type AppsManifestDeleteResponse struct {
	Ok bool `json:"ok"`
}

func (r AppsManifestDeleteResponse) IsOk() bool {
	return r.Ok
}

func (r AppsManifestDeleteResponse) logFields() map[string]any {
	return nil
}

func (c *Client) AppsManifestDelete(
	ctx context.Context,
	request AppsManifestDeleteRequest,
) (*AppsManifestDeleteResponse, error) {
	return callMethod[AppsManifestDeleteResponse](ctx, c, "apps.manifest.delete", &request)
}

type ToolingTokensRotateResponse struct {
	Ok           bool                         `json:"ok"`
	Token        tokens.AppConfigurationToken `json:"token"`
	RefreshToken tokens.RefreshToken          `json:"refresh_token"`
	IssuedAt     UnixTimestamp                `json:"iat"`
	ExpiresAt    UnixTimestamp                `json:"exp"`
}

func (r ToolingTokensRotateResponse) IsOk() bool {
	return r.Ok
}

// logFields leaves out Token and RefreshToken. The token can change every
// app in the workspace, and the refresh token can mint new tokens.
func (r ToolingTokensRotateResponse) logFields() map[string]any {
	return map[string]any{
		"issued_at":  r.IssuedAt.Time().UTC().Format(time.RFC3339),
		"expires_at": r.ExpiresAt.Time().UTC().Format(time.RFC3339),
	}
}

func (c *Client) ToolingTokensRotate(
	ctx context.Context,
	refreshToken tokens.RefreshToken,
) (*ToolingTokensRotateResponse, error) {
	values := url.Values{}
	values.Set("refresh_token", string(refreshToken))

	httpRequest, err := c.createFormRequest(ctx, http.MethodPost, "tooling.tokens.rotate", values)
	if err != nil {
		return nil, err
	}

	httpResponse, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}

	return readJSONResponse[ToolingTokensRotateResponse](ctx, "tooling.tokens.rotate", httpResponse)
}

// callMethod calls methodName with the client's app configuration token.
// When Slack refuses the token as expired or revoked, it gets another and
// calls once more.
func callMethod[T response](ctx context.Context, c *Client, methodName string, request any) (*T, error) {
	if c.serviceToken != "" {
		response, err := callMethodWithToken[T](ctx, c, methodName, c.serviceToken, request)

		return response, explainServiceTokenError(err)
	}

	token, err := c.tokens.Get(ctx)
	if err != nil {
		return nil, err
	}

	response, err := callMethodWithToken[T](ctx, c, methodName, token, request)
	if !isTokenRefusedError(err) || !c.tokens.MarkAsRefused(token) {
		return response, err
	}

	tflog.Debug(ctx, "Slack refused the app configuration token, refreshing token.", map[string]any{"method": methodName})

	token, refreshErr := c.tokens.Get(ctx)
	if refreshErr != nil {
		return nil, fmt.Errorf("%w, and getting another token failed: %w", err, refreshErr)
	}

	return callMethodWithToken[T](ctx, c, methodName, token, request)
}

func callMethodWithToken[T response](
	ctx context.Context,
	c *Client,
	methodName string,
	token tokens.AppConfigurationToken,
	request any,
) (*T, error) {
	httpResponse, err := c.send(ctx, methodName, func() (*http.Request, error) {
		return c.createJSONRequest(ctx, http.MethodPost, methodName, token, request)
	})
	if err != nil {
		return nil, err
	}

	return readJSONResponse[T](ctx, methodName, httpResponse)
}

// BotToken is an installed app's bot token. It prints as [redacted];
// string(t) gives the value.
type BotToken string

func (t BotToken) String() string { return "[redacted]" }

func (t BotToken) GoString() string { return "[redacted]" }

type AppsDeveloperInstallRequest struct {
	AppID string `json:"app_id"`
}

type AppsDeveloperInstallResponse struct {
	Ok              bool `json:"ok"`
	APIAccessTokens struct {
		Bot BotToken `json:"bot"`
	} `json:"api_access_tokens"`
}

func (r AppsDeveloperInstallResponse) IsOk() bool {
	return r.Ok
}

// logFields leaves out APIAccessTokens: they are the app's secrets.
func (r AppsDeveloperInstallResponse) logFields() map[string]any {
	return nil
}

// AppsDeveloperInstall installs the app in the token owner's workspace, and
// returns its bot token. Installing again returns the same bot token.
func (c *Client) AppsDeveloperInstall(
	ctx context.Context,
	request AppsDeveloperInstallRequest,
) (*AppsDeveloperInstallResponse, error) {
	return callMethod[AppsDeveloperInstallResponse](ctx, c, "apps.developerInstall", &request)
}

type AuthTestResponse struct {
	Ok     bool   `json:"ok"`
	TeamID string `json:"team_id"`
	UserID string `json:"user_id"`
	BotID  string `json:"bot_id"`
}

func (r AuthTestResponse) IsOk() bool {
	return r.Ok
}

func (r AuthTestResponse) logFields() map[string]any {
	return map[string]any{"team_id": r.TeamID, "user_id": r.UserID, "bot_id": r.BotID}
}

// AuthTest names the workspace, user and bot that botToken acts as.
func (c *Client) AuthTest(ctx context.Context, botToken BotToken) (*AuthTestResponse, error) {
	return callMethodWithToken[AuthTestResponse](ctx, c, "auth.test", tokens.AppConfigurationToken(botToken), struct{}{})
}

type BotsInfoRequest struct {
	Bot string
}

type BotsInfoResponse struct {
	Ok  bool `json:"ok"`
	Bot struct {
		Icons struct {
			Image72 string `json:"image_72"`
		} `json:"icons"`
	} `json:"bot"`
}

func (r BotsInfoResponse) IsOk() bool {
	return r.Ok
}

func (r BotsInfoResponse) logFields() map[string]any {
	return nil
}

// BotsInfo returns a bot's profile, including the URL Slack serves its
// icon at. The URL changes on every apps.icon.set, even with the same image.
func (c *Client) BotsInfo(ctx context.Context, request BotsInfoRequest) (*BotsInfoResponse, error) {
	const methodName = "bots.info"

	values := url.Values{}
	values.Set("bot", request.Bot)

	return callManagementMethodWith[BotsInfoResponse](ctx, c, methodName, func(token tokens.AppConfigurationToken) (*http.Request, error) {
		httpRequest, err := c.createRequest(ctx, http.MethodPost, methodName, token, bytes.NewBufferString(values.Encode()))
		if err != nil {
			return nil, err
		}
		httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return httpRequest, nil
	})
}

type AppsIconSetRequest struct {
	AppID    string
	FileName string
	Image    []byte
}

type AppsIconSetResponse struct {
	Ok bool `json:"ok"`
}

func (r AppsIconSetResponse) IsOk() bool {
	return r.Ok
}

func (r AppsIconSetResponse) logFields() map[string]any {
	return nil
}

// AppsIconSet replaces the app's icon. Slack takes a PNG, JPEG or GIF of 512
// to 2000 pixels per side, and treats every call as a change.
func (c *Client) AppsIconSet(ctx context.Context, request AppsIconSetRequest) (*AppsIconSetResponse, error) {
	const methodName = "apps.icon.set"

	return callManagementMethodWith[AppsIconSetResponse](ctx, c, methodName, func(token tokens.AppConfigurationToken) (*http.Request, error) {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		if err := form.WriteField("app_id", request.AppID); err != nil {
			return nil, err
		}
		part, err := form.CreateFormFile("file", filepath.Base(request.FileName))
		if err != nil {
			return nil, err
		}
		if _, err := part.Write(request.Image); err != nil {
			return nil, err
		}
		if err := form.Close(); err != nil {
			return nil, err
		}

		httpRequest, err := c.createRequest(ctx, http.MethodPost, methodName, token, &body)
		if err != nil {
			return nil, err
		}
		httpRequest.Header.Set("Content-Type", form.FormDataContentType())

		return httpRequest, nil
	})
}

// callManagementMethodWith calls a method whose body is not JSON, with the
// token every app management call carries.
func callManagementMethodWith[T response](
	ctx context.Context,
	c *Client,
	methodName string,
	newRequest func(token tokens.AppConfigurationToken) (*http.Request, error),
) (*T, error) {
	token := c.serviceToken
	if token == "" {
		var err error
		if token, err = c.tokens.Get(ctx); err != nil {
			return nil, err
		}
	}

	httpResponse, err := c.send(ctx, methodName, func() (*http.Request, error) { return newRequest(token) })
	if err != nil {
		return nil, err
	}

	response, err := readJSONResponse[T](ctx, methodName, httpResponse)
	if c.serviceToken != "" {
		err = explainServiceTokenError(err)
	}

	return response, err
}
