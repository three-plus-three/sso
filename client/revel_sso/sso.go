package revel_sso

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/revel/revel"
	sso "github.com/three-plus-three/sso/client"
)

type CheckFunc func(c *revel.Controller) revel.Result

func SSO(ssoClient *sso.Client, maxAge time.Duration, getURL func(req *http.Request) string) CheckFunc {
	return func(c *revel.Controller) revel.Result {
		if sso.SessionIsExpiredOrMissing(c.Session[sso.SESSION_EXPIRE_KEY]) ||
			sso.SessionIsInvalid(c.Session[sso.SESSION_VALID_KEY]) {

			var currentURL string
			if getURL != nil {
				currentURL = getURL(c.Request.Request)
			} else {
				currentURL = c.Request.Request.URL.String()
			}

			serviceTicket := c.Params.Query.Get("ticket")
			if serviceTicket == "" {
				//c.RenderArgs["error"] = "ticket 为空"
				//return c.RenderError(errors.New("访问授权系统失败 - 会话已注销"))
				return c.Redirect(ssoClient.LoginURL(currentURL))
			}

			ticket, err := ssoClient.ValidateTicket(serviceTicket, currentURL)
			if err != nil {
				c.Response.Status = http.StatusUnauthorized
				return c.RenderError(errors.New("验证 ticket 失败，" + err.Error()))
			}

			c.Session[sso.SESSION_VALID_KEY] = "true"
			if user, ok := ticket.Claims["username"]; ok && user != nil {
				c.Session[sso.SESSION_USER_KEY] = fmt.Sprint(user)
			}
		}

		return nil
	}
}

/*
type Handlers struct {
	SessionFilter func(c *revel.Controller, fc []revel.Filter)
	Login         func(c *revel.Controller, name string) revel.Result
	Logout        func(c *revel.Controller, name string) revel.Result
}

func SSOHandlers(withSessions sessions.WithSessions, ssoClient *sso.Client) Handlers {
	restricted := func(c *revel.Controller, fc []revel.Filter) {
		sess, err := withSessions.GetSession(c.Request.Request)
		if err != nil {
			revel.WARN.Println("fetch session fail,", err)
			//http.Redirect(c.Response.Out, c.Request.Request, ssoClient.LoginURL(""), http.StatusTemporaryRedirect)
			//return
		}

		// if sess == nil {
		// 	revel.WARN.Println("session isn't found")

		// 	sess, err = withSessions.CreateSession(nil, "", map[string]interface{}{"username": "guest"})
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// }

		// if !sess.Valid() {
		// 	http.Redirect(c.Response.Out, c.Request.Request, ssoClient.LoginURL(""), http.StatusTemporaryRedirect)
		// 	return
		// }
		if c.Session == nil {
			c.Session = revel.Session{}
		}

		if sess != nil {
			sess.ForEach(func(key string, value interface{}) {
				c.Session[key] = fmt.Sprint(value)
			})
			c.RenderArgs["context"] = sess
		}
		//sessionWasEmpty := len(c.Session) == 0

		// Make session vars available in templates as {{.session.xyz}}
		c.RenderArgs["session"] = c.Session

		fc[0](c, fc[1:])

		if sess != nil {
			// Store the signed session if it could have changed.
			//if len(c.Session) > 0 || !sessionWasEmpty {
			for k, v := range c.Session {
				sess.Set(k, v)
			}
			c.SetCookie(withSessions.SessionCookie(sess))
			//}
		}
	}

	login := func(c *revel.Controller, name string) revel.Result {
		serviceTicket := c.Params.Query.Get("ticket")
		if serviceTicket == "" {
			c.RenderArgs["error"] = "ticket 为空"
			return c.RenderTemplate(name)
		}

		ticket, err := ssoClient.ValidateTicket(serviceTicket, withSessions.CurrentURL(c.Request.Request))
		if err != nil {
			c.RenderArgs["error"] = "验证 ticket 失败，" + err.Error()
			return c.RenderTemplate(name)
		}
		sess, err := withSessions.CreateSession(c.Request.Request, "", ticket.Claims)
		if err != nil {
			c.RenderArgs["error"] = "创建会话失败，" + err.Error()
			return c.RenderTemplate(name)
		}

		sess.ForEach(func(key string, value interface{}) {
			c.Session[key] = fmt.Sprint(value)
		})
		c.RenderArgs["context"] = sess

		service := c.Params.Query.Get("return")
		if service != "" {
			c.Response.Status = http.StatusTemporaryRedirect
			return c.Redirect(service)
		}

		c.RenderArgs["success"] = "登录成功"
		return c.RenderTemplate(name)
	}

	logout := func(c *revel.Controller, name string) revel.Result {
		sess, err := withSessions.GetSession(c.Request.Request)
		if err != nil {
			revel.WARN.Println("fetch session failed,", err)
		}
		if sess != nil {
			sess.SetValid(false)
		}
		withSessions.RemoveSession(c.Request.Request)

		service := c.Params.Query.Get("return")
		if service != "" {
			c.Response.Status = http.StatusTemporaryRedirect
			return c.Redirect(service)
		}
		c.RenderArgs["success"] = "注销成功"
		return c.RenderTemplate(name)
	}

	return Handlers{
		SessionFilter: restricted,
		Login:         login,
		Logout:        logout,
	}
}
*/
