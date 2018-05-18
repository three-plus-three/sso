package client

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Option struct {
	URL         string
	SessionPath string
	SessionKey  string
	SessionHash func() hash.Hash
	SecretKey   []byte
	CurrentURL  func(*http.Request) url.URL
}

func SSO(opt *Option) func(w http.ResponseWriter, req *http.Request, noAuth, next http.Handler) {
	ssoClient, err := NewClient(opt.URL)
	if err != nil {
		panic(err)
	}

	sessionKey := opt.SessionKey
	if sessionKey == "" {
		sessionKey = DefaultSessionKey
	}
	sessionPath := opt.SessionPath
	secretKey := opt.SecretKey

	if sessionPath == "" {
		sessionPath = "/" // 必须指定 Path, 否则会被自动赋成当前请求的 url 中的 path
	} else if !strings.HasPrefix(sessionPath, "/") {
		sessionPath = "/" + sessionPath
	}

	currentURL := opt.CurrentURL
	if currentURL == nil {
		currentURL = func(req *http.Request) url.URL {
			return *req.URL
		}
	}

	h := opt.SessionHash
	if h == nil {
		h = sha1.New
	}

	return func(w http.ResponseWriter, req *http.Request, noAuth, next http.Handler) {
		sess, err := GetValues(req, sessionKey, h, secretKey)
		if err != nil {
			queryParam := req.URL.Query()
			serviceTicket := queryParam.Get("ticket")
			if serviceTicket == "" {
				log.Println("fetch session fail,", err)
				noAuth.ServeHTTP(w, req)
				return
			}

			currentRequestURL := currentURL(req)
			ticket, err := ssoClient.ValidateTicket(serviceTicket, currentRequestURL.String())
			if err != nil {
				log.Println("validate ticket fail,", err)
				noAuth.ServeHTTP(w, req)
				return
			}

			var values = url.Values{}
			for k, v := range ticket.Claims {
				values.Set(k, fmt.Sprint(v))
			}
			values.Set(SESSION_ID_KEY, ticket.SessionID)
			values.Set(SESSION_EXPIRE_KEY, "session")
			values.Set(SESSION_VALID_KEY, "true")
			if user, ok := ticket.Claims["username"]; ok {
				values.Set(SESSION_USER_KEY, fmt.Sprint(user))
			}

			http.SetCookie(w, &http.Cookie{Name: sessionKey,
				Value: Encode(values, h, secretKey),
				Path:  sessionPath})

			service := queryParam.Get("return")
			if service != "" {
				http.Redirect(w, req, service, http.StatusTemporaryRedirect)
				return
			}
			next.ServeHTTP(w, req)
			return
		}

		if sess == nil {
			log.Println("session isn't found")
			noAuth.ServeHTTP(w, req)
			return
		}

		if IsInvalid(sess) {
			log.Println("session is invalid")
			noAuth.ServeHTTP(w, req)
			return
		}

		next.ServeHTTP(w, req)
	}
}
