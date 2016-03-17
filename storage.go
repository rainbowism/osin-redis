package osinredis

import (
	"encoding/json"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"github.com/rainbowism/osin"
	"reflect"
	"strings"
	"time"
)

// Storage complies with the osin.Storage interface
type Storage struct {
	pool *redis.Pool
}

// New creates a new storage given a connection
func New(pool *redis.Pool) *Storage {
	r := &Storage{pool}
	return r
}

// Clone copies the storage
func (s *Storage) Clone() osin.Storage {
	return s
}

// Close cleans up all the resources
func (s *Storage) Close() {}

// CreateClient creates a client
func (s *Storage) CreateClient(c osin.Client) error {
	data, err := assertToString(c.GetUserData())
	if err != nil {
		return err
	}
	conn := s.pool.Get()
	defer conn.Close()
	_, err = conn.Do("HMSET", "c:"+c.GetId(),
		"secret", c.GetSecret(),
		"redirect_uri", c.GetRedirectUri(),
		"data", data,
	)
	return err
}

// GetClient retrieves a client
func (s *Storage) GetClient(id string) (osin.Client, error) {
	conn := s.pool.Get()
	defer conn.Close()
	values, err := redis.Values(conn.Do("HGETALL", "c:"+id))
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, ErrClientNotFound
	}
	var c osin.DefaultClient
	c.Id = id
	for i := 0; i < len(values); i += 2 {
		key, rediserr := redis.String(values[i], err)
		if rediserr != nil {
			return nil, rediserr
		}
		switch key {
		case "secret":
			secret, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			c.Secret = secret
		case "redirect_uri":
			redirectURI, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			c.RedirectUri = redirectURI
		case "data":
			userData, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			c.UserData = userData
		}
	}
	return &c, nil
}

// UpdateClient updates a client
func (s *Storage) UpdateClient(c osin.Client) error {
	data, err := assertToString(c.GetUserData())
	if err != nil {
		return err
	}
	conn := s.pool.Get()
	defer conn.Close()
	_, err = conn.Do("HMSET", "c:"+c.GetId(),
		"secret", c.GetSecret(),
		"redirect_uri", c.GetRedirectUri(),
		"data", data,
	)
	return err
}

// RemoveClient removes a client
func (s *Storage) RemoveClient(id string) error {
	conn := s.pool.Get()
	defer conn.Close()
	_, err := conn.Do("DEL", "c:"+id)
	return err
}

// SaveAuthorize saves authorize data
func (s *Storage) SaveAuthorize(data *osin.AuthorizeData) error {
	extra, err := assertToString(data.UserData)
	if err != nil {
		return err
	}
	conn := s.pool.Get()
	defer conn.Close()
	_, err = conn.Do("HMSET", "a:"+data.Code,
		"client", data.Client.GetId(),
		"expires_in", data.ExpiresIn,
		"scope", data.Scope,
		"redirect_uri", data.RedirectUri,
		"state", data.State,
		"created_at", data.CreatedAt.Unix(),
		"extra", extra,
	)
	if err != nil {
		return err
	}
	_, err = conn.Do("EXPIREAT", "a:"+data.Code, data.ExpireAt().Unix())
	return err
}

// LoadAuthorize loads AuthorizeData by a code
func (s *Storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	conn := s.pool.Get()
	defer conn.Close()
	values, err := redis.Values(conn.Do("HGETALL", "a:"+code))
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, ErrAuthorizeCodeNotFound
	}
	var data osin.AuthorizeData
	data.Code = code
	for i := 0; i < len(values); i += 2 {
		key, rediserr := redis.String(values[i], err)
		if rediserr != nil {
			return nil, rediserr
		}
		switch key {
		case "client":
			cid, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			client, err := s.GetClient(cid)
			if err != nil {
				return nil, err
			}
			data.Client = client
		case "expires_in":
			expiresIn, err := redis.Int(values[i+1], err)
			if err != nil {
				return nil, err
			}
			data.ExpiresIn = int32(expiresIn)
		case "scope":
			scope, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			data.Scope = scope
		case "redirect_uri":
			redirectURI, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			data.RedirectUri = redirectURI
		case "state":
			state, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			data.State = state
		case "created_at":
			createdAt, err := redis.Int64(values[i+1], err)
			if err != nil {
				return nil, err
			}
			data.CreatedAt = time.Unix(createdAt, 0)
		case "extra":
			userData, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			data.UserData = userData
		}
	}
	return &data, nil
}

// RemoveAuthorize revokes an authorization code
func (s *Storage) RemoveAuthorize(code string) error {
	conn := s.pool.Get()
	defer conn.Close()
	_, err := conn.Do("DEL", "a:"+code)
	return err
}

// SaveAccess writes AccessData
func (s *Storage) SaveAccess(data *osin.AccessData) error {
	var prev string
	authorizeData := &osin.AuthorizeData{}

	if data.AccessData != nil {
		prev = data.AccessData.AccessToken
	}

	if data.AuthorizeData != nil {
		authorizeData = data.AuthorizeData
	}

	extra, err := assertToString(data.UserData)
	if err != nil {
		return err
	}

	conn := s.pool.Get()
	defer conn.Close()

	if len(data.RefreshToken) != 0 {
		if err := conn.Send("HMSET", "r:"+data.RefreshToken,
			"access", data.AccessToken); err != nil {
			return err
		}
		if err = conn.Send("EXPIREAT", "r:"+data.RefreshToken, data.CreatedAt.AddDate(0, 0, 7).Unix()); err != nil {
			return err
		}
	}

	if data.Client == nil {
		return ErrClientIsNil
	}

	if err = conn.Send("HMSET", "t:"+data.AccessToken,
		"client", data.Client.GetId(),
		"authorize", authorizeData.Code,
		"previous", prev,
		"refresh_token", data.RefreshToken,
		"expires_in", data.ExpiresIn,
		"scope", data.Scope,
		"redirect_uri", data.RedirectUri,
		"created_at", data.CreatedAt.Unix(),
		"extra", extra,
	); err != nil {
		return err
	}

	if err = conn.Send("EXPIREAT", "t:"+data.AccessToken, data.CreatedAt.AddDate(0, 0, 7).Unix()); err != nil {
		return err
	}

	return conn.Flush()
}

// LoadAccess loads AccessData by a token
func (s *Storage) LoadAccess(token string) (*osin.AccessData, error) {
	conn := s.pool.Get()
	defer conn.Close()
	values, err := redis.Values(conn.Do("HGETALL", "t:"+token))
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, ErrAccessTokenNotFound
	}
	var result osin.AccessData
	result.AccessToken = token
	for i := 0; i < len(values); i += 2 {
		key, rediserr := redis.String(values[i], err)
		if rediserr != nil {
			return nil, rediserr
		}
		switch key {
		case "client":
			cid, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			client, err := s.GetClient(cid)
			if err != nil {
				return nil, err
			}
			result.Client = client
		case "authorize":
			auth, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			result.AuthorizeData, _ = s.LoadAuthorize(auth)
		case "previous":
			prev, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			result.AccessData, _ = s.LoadAccess(prev)
		case "refresh_token":
			token, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			result.RefreshToken = token
		case "expires_in":
			expiresIn, err := redis.Int(values[i+1], err)
			if err != nil {
				return nil, err
			}
			result.ExpiresIn = int32(expiresIn)
		case "scope":
			scope, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			result.Scope = scope
		case "redirect_uri":
			redirectURI, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			result.RedirectUri = redirectURI
		case "created_at":
			createdAt, err := redis.Int64(values[i+1], err)
			if err != nil {
				return nil, err
			}
			result.CreatedAt = time.Unix(createdAt, 0)
		case "extra":
			userData, rediserr := redis.String(values[i+1], err)
			if rediserr != nil {
				return nil, rediserr
			}
			result.UserData = userData
		}
	}
	return &result, nil
}

// RemoveAccess revokes an access token
func (s *Storage) RemoveAccess(token string) error {
	conn := s.pool.Get()
	defer conn.Close()
	_, err := conn.Do("DEL", "t:"+token)
	return err
}

// LoadRefresh retrieves refresh AccessData
func (s *Storage) LoadRefresh(token string) (*osin.AccessData, error) {
	conn := s.pool.Get()
	defer conn.Close()
	values, err := redis.Values(conn.Do("HMGET", "r:"+token, "access"))
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, ErrRefreshTokenNotFound
	}
	access, err := redis.String(values[0], err)
	if err != nil {
		return nil, err
	}
	return s.LoadAccess(access)
}

// RemoveRefresh revokes refresh AccessData
func (s *Storage) RemoveRefresh(token string) error {
	conn := s.pool.Get()
	defer conn.Close()
	_, err := conn.Do("DEL", "r:"+token)
	return err
}

func assertToString(in interface{}) (string, error) {
	var ok bool
	var data string
	if in == nil {
		return "", nil
	} else if data, ok = in.(string); ok {
		return data, nil
	} else if str, ok := in.(fmt.Stringer); ok {
		return str.String(), nil
	} else if strings.Contains(reflect.TypeOf(in).String(), "struct") {
		//Added for struct
		out, err := json.Marshal(in)
		if err != nil {
			return "", err
		}
		return string(out), nil

	}
	return "", fmt.Errorf("Could not assert \"%v\" to string", in)
}
