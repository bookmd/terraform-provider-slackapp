package slack

import (
	"errors"
	"fmt"
)

type ErrorResponse struct {
	Ok     bool   `json:"ok"`
	Error_ string `json:"error"`
	Errors []struct {
		Message string `json:"message"`
		Pointer string `json:"pointer"`
	} `json:"errors"`
}

func (e *ErrorResponse) IsOk() bool {
	return e.Ok
}

func (e *ErrorResponse) Error() string {
	return e.Error_
}

// IsAppNotFoundError reports whether err, or an error it wraps, is Slack
// answering app_not_found: the app does not exist, or the token cannot see
// it.
func IsAppNotFoundError(err error) bool {
	var slackErr *ErrorResponse

	return errors.As(err, &slackErr) && slackErr.Error_ == "app_not_found"
}

// IsAlreadyOwnerError reports whether err, or an error it wraps, is Slack
// answering user_already_owner: the user already is a collaborator of the app.
func IsAlreadyOwnerError(err error) bool {
	var slackErr *ErrorResponse

	return errors.As(err, &slackErr) && slackErr.Error_ == "user_already_owner"
}

// IsUserNotFoundError reports whether err, or an error it wraps, is Slack
// answering user_not_found.
func IsUserNotFoundError(err error) bool {
	var slackErr *ErrorResponse

	return errors.As(err, &slackErr) && slackErr.Error_ == "user_not_found"
}

// isTokenRefusedError reports whether err, or an error it wraps, is Slack
// refusing the app configuration token in a way another token cures:
// token_expired after its 12 hours, or token_revoked once a rotation
// replaced it (seen 2026-10, against a test workspace).
//
//declscope:shared // methods.go gets a new token on it
func isTokenRefusedError(err error) bool {
	var slackErr *ErrorResponse

	return errors.As(err, &slackErr) && (slackErr.Error_ == "token_expired" || slackErr.Error_ == "token_revoked")
}

// explainServiceTokenError adds what to do to an error that means Slack no
// longer takes the service token. A service token is never rotated, so only a
// person can replace it.
//
//declscope:shared
func explainServiceTokenError(err error) error {
	var slackErr *ErrorResponse
	if !errors.As(err, &slackErr) {
		return err
	}

	switch slackErr.Error_ {
	case "invalid_auth", "not_authed", "token_revoked", "token_expired", "account_inactive":
		return fmt.Errorf("slack refused the service token (%w). "+
			"Issue a new one with `slack auth token`, signed in as an App Manager of the workspace, "+
			"and replace the token where the provider reads it", err)
	default:
		return err
	}
}
