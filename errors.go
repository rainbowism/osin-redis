package osinredis

import "errors"

// Errors
var (
	ErrClientNotFound        = errors.New("osinredis: client not found")
	ErrClientIsNil           = errors.New("osinredis: client must not be nil")
	ErrAuthorizeCodeNotFound = errors.New("osinredis: authorize code not found")
	ErrAccessTokenNotFound   = errors.New("osinredis: access token not found")
	ErrRefreshTokenNotFound  = errors.New("osinredis: refresh token not found")
)
