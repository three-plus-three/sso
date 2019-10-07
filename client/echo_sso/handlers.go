package echo_sso

import (
	"hash"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo"
	sso "github.com/three-plus-three/sso/client"
)

/*
// SSO 创建一个 SSO 的 MiddlewareFunc
func SSO(ssoClient *sso.Client) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			sess, err := srv.GetSession(c.Request())
			if err != nil {
				return err
			}
			if sess != nil {
				if sess.Valid() {
					c.SetCookie(srv.SessionCookie(sess))
					c.Set("EchoSession", sess)
					return next(c)
				}
			}
			serviceTicket := c.QueryParam("ticket")
			if serviceTicket != "" {
				ticket, err := ssoClient.ValidateTicket(serviceTicket, srv.CurrentURL(c.Request()))
				if err != nil {
					return err
				}

				sess, err := srv.CreateSession(c.Request(), ticket.SessionID, ticket.Claims)
				if err != nil {
					return err
				}

				c.SetCookie(srv.SessionCookie(sess))
				c.Set("EchoSession", sess)
				return next(c)
			}

			return c.Redirect(http.StatusTemporaryRedirect, ssoClient.LoginURL(srv.CurrentURL(c.Request())))
		}
	}
}
*/

type Handlers struct {
	Restricted echo.MiddlewareFunc
	Login      echo.HandlerFunc
	Logout     echo.HandlerFunc
}

func SSOHandlers(sessionKey, sessionPath string, h func() hash.Hash, secretKey []byte, currentURL func(*http.Request) url.URL) Handlers {
	if sessionPath == "" {
		sessionPath = "/" // 必须指定 Path, 否则会被自动赋成当前请求的 url 中的 path
	} else if !strings.HasPrefix(sessionPath, "/") {
		sessionPath = "/" + sessionPath
	}

	if currentURL == nil {
		currentURL = func(req *http.Request) url.URL {
			return *req.URL
		}
	}

	restricted := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			sess, err := sso.GetValues(c.Request(), sessionKey, h, secretKey)
			if err != nil {
				log.Println("fetch session fail,", err)
				return echo.ErrUnauthorized
			}

			if sess == nil {
				log.Println("session isn't found")
				return echo.ErrUnauthorized
			}

			if sso.IsInvalid(sess) {
				log.Println("session is invalid")
				return echo.ErrUnauthorized
			}

			//c.SetCookie(withSessions.SessionCookie(sess))
			//c.Set("EchoSession", sess)
			return next(c)
		}
	}

	login := func(c echo.Context) error {
		// serviceTicket := c.QueryParam("ticket")
		// if serviceTicket == "" {
		// 	return echo.ErrUnauthorized
		// }

		// currentRequestURL := currentURL(c.Request())
		// ticket, err := ssoClient.ValidateTicket(serviceTicket, currentRequestURL.String())
		// if err != nil {
		// 	return err
		// }

		// var values = url.Values{}
		// for k, v := range ticket.Claims {
		// 	values.Set(k, fmt.Sprint(v))
		// }
		// values.Set(sso.SESSION_ID_KEY, ticket.SessionID)
		// values.Set(sso.SESSION_EXPIRE_KEY, "session")
		// values.Set(sso.SESSION_VALID_KEY, "true")
		// if user, ok := ticket.Claims["username"]; ok {
		// 	values.Set(sso.SESSION_USER_KEY, fmt.Sprint(user))
		// }
		// c.SetCookie(&http.Cookie{Name: sessionKey,
		// 	Value: sso.Encode(values, h, secretKey),
		// 	Path:  sessionPath})

		service := c.QueryParam("return")
		if service != "" {
			return c.Redirect(http.StatusTemporaryRedirect, service)
		}
		return c.JSON(http.StatusOK, "OK")
	}

	logout := func(c echo.Context) error {
		c.SetCookie(&http.Cookie{Name: sessionKey,
			Value:   "",
			Path:    sessionPath,
			Expires: time.Now()})
		service := c.QueryParam("return")
		if service != "" {
			return c.Redirect(http.StatusTemporaryRedirect, service)
		}
		return c.String(http.StatusOK, "OK")
	}

	return Handlers{
		Restricted: restricted,
		Login:      login,
		Logout:     logout,
	}
}
