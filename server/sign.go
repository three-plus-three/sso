package server

import (
	"errors"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

// ErrSignatureInvalid Specific instances for HS256 and company
var ErrSignatureInvalid = jwt.ErrSignatureInvalid

// SigningMethod Implement SigningMethod to add new methods for signing or verifying tokens.
type SigningMethod interface {
	Verify(signingString, signature string, key interface{}) error // Returns nil if signature is valid
	Sign(signingString string, key interface{}) (string, error)    // Returns encoded signature or error
	Alg() string                                                   // returns the alg identifier for this method (example: 'HS256')
}

// RegisterSigningMethod Register the "alg" name and a factory function for signing method.
// This is typically done during init() in the method's implementation
func RegisterSigningMethod(alg string, f func() SigningMethod) {
	jwt.RegisterSigningMethod(alg, func() jwt.SigningMethod {
		return f()
	})
}

// GetSigningMethod Get a signing method from an "alg" string
func GetSigningMethod(alg string) SigningMethod {
	return jwt.GetSigningMethod(alg)
}

type signingMethodDefault struct{}

var methodDefault = &signingMethodDefault{}

func init() {
	RegisterSigningMethod(methodDefault.Alg(), func() SigningMethod {
		return methodDefault
	})
}

func (m *signingMethodDefault) Alg() string {
	return "default"
}

// Only allow 'none' alg type if UnsafeAllowNoneSignatureType is specified as the key
func (m *signingMethodDefault) Verify(signingString, signature string, key interface{}) (err error) {
	// If signing method is none, signature must be an empty string
	if signature != signingString {
		return jwt.ErrSignatureInvalid
	}

	// Accept 'none' signing method.
	return nil
}

// Only allow 'none' signing if UnsafeAllowNoneSignatureType is specified as the key
func (m *signingMethodDefault) Sign(signingString string, key interface{}) (string, error) {
	return signingString, nil
}

func readVerify(config *Config) (func(string, string) error, error) {
	var signingMethod SigningMethod = methodDefault
	var secretKey []byte

	params, ok := config.AuthConfig.(map[string]interface{})
	if ok && params != nil {
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
				hashKey = strings.TrimSpace(s)
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

	return func(password, excepted string) error {
		return signingMethod.Verify(password, excepted, secretKey)
	}, nil
}
