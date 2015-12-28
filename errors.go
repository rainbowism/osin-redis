package osinredis

import "errors"

// Errors
var (
	ErrClientNotFound       = errors.New("osinredis: client not found")
	ErrClientIsNil          = errors.New("osinredis: client must not be nil")
	ErrAuthorizeCodeExpired = errors.New("osinredis: authorize code expired")
	ErrAccessTokenExpired   = errors.New("osinredis: access token expired")
	ErrRefreshTokenExpired  = errors.New("osinredis: refresh token expired")
)
