package server

import (
	"errors"
	"net/http"
)

// DefaultAuthenticationHandler 缺省 AuthenticationHandler
var DefaultAuthenticationHandler = CreateUserAuthenticationHandler

// AuthenticationHandler 验证用户并返回用户信息
type AuthenticationHandler interface {
	Auth(req *http.Request, username, password string) (bool, map[string]interface{}, error)
}

func CreateUserAuthenticationHandler(userHandler UserHandler, config interface{}) (AuthenticationHandler, error) {
	var params map[string]interface{}
	if config != nil {
		m, ok := config.(map[string]interface{})
		if !ok {
			return nil, errors.New("arguments of AuthConfg isn't map")
		}
		params = m
	}

	var signingMethod SigningMethod = methodDefault
	var secretKey []byte

	if params != nil {
		if o, ok := params["passwordHashAlg"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("数据库配置中的 passwordHashAlg 的值不是字符串")
			}

			var hashKey string
			if k, ok := params["passwordHashKey"]; ok && k != nil {
				s, ok := k.(string)
				if !ok {
					return nil, errors.New("数据库配置中的 passwordHashKey 的值不是字符串")
				}
				hashKey = s
			}

			signingMethod = GetSigningMethod(s)
			if signingMethod == nil {
				return nil, errors.New("在数据库配置中的 passwordHashAlg 的算法不支持")
			}
			if hashKey != "" {
				secretKey = []byte(hashKey)
			}
		}
	}

	return &userAuthenticationHandler{
		userHandler:   userHandler,
		signingMethod: signingMethod,
		secretKey:     secretKey,
	}, nil
}

type userAuthenticationHandler struct {
	userHandler   UserHandler
	signingMethod SigningMethod
	secretKey     []byte
}

func (ah *userAuthenticationHandler) Auth(req *http.Request, username, password string) (bool, map[string]interface{}, error) {
	if username == "" {
		return false, nil, ErrUsernameEmpty
	}

	users, err := ah.userHandler.ReadUser(username)
	if err != nil {
		return false, nil, err
	}
	if len(users) == 0 {
		return false, nil, ErrUserNotFound
	}
	if len(users) != 1 {
		return false, nil, ErrMutiUsers
	}

	ok, err := users[0].CanUse(req)
	if err != nil {
		return false, nil, err
	}
	if !ok {
		return false, nil, errors.New("user is inused")
	}

	exceptedPassword := users[0].Password()
	if exceptedPassword == "" {
		return false, nil, ErrPasswordEmpty
	}

	err = ah.signingMethod.Verify(password, exceptedPassword, ah.secretKey)
	if err != nil {
		if err == ErrSignatureInvalid {
			return false, nil, ErrPasswordNotMatch
		}
		return false, nil, err
	}
	return true, users[0].Data(), nil
}
