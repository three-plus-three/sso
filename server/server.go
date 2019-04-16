package server

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/mojocn/base64Captcha"
	"github.com/three-plus-three/sso/users"
)

var (
	isDebug = os.Getenv("IsSSODebug") == "true"

	// ErrUsernameEmpty 用户名为空
	ErrUsernameEmpty = users.ErrUsernameEmpty

	// ErrPasswordEmpty 密码为空
	ErrPasswordEmpty = users.ErrPasswordEmpty

	// ErrUserNotFound 用户未找到
	ErrUserNotFound = users.ErrUserNotFound

	// ErrPasswordNotMatch 密码不正确
	ErrPasswordNotMatch = users.ErrPasswordNotMatch

	// ErrMutiUsers 找到多个用户
	ErrMutiUsers = users.ErrMutiUsers

	// ErrUserLocked 用户已被锁定
	ErrUserLocked = users.ErrUserLocked

	// ErrUserIPBlocked 用户不在指定的 IP 范围登录
	ErrUserIPBlocked = users.ErrUserIPBlocked

	// ErrServiceTicketNotFound Service ticket 没有找到
	ErrServiceTicketNotFound = users.ErrServiceTicketNotFound

	// ErrServiceTicketExpired Service ticket 已过期
	ErrServiceTicketExpired = users.ErrServiceTicketExpired

	// ErrUnauthorizedService Service 是未授权的
	ErrUnauthorizedService = users.ErrUnauthorizedService

	// ErrUserAlreadyOnline 用户已登录
	ErrUserAlreadyOnline = users.ErrUserAlreadyOnline

	// ErrPermissionDenied 没有权限
	ErrPermissionDenied = users.ErrPermissionDenied

	// ErrCaptchaKey
	ErrCaptchaKey = users.ErrCaptchaKey

	// ErrCaptchaMissing
	ErrCaptchaMissing = users.ErrCaptchaMissing
)

type ErrExternalServer = users.ErrExternalServer

var IsErrExternalServer = users.IsErrExternalServer

// TicketGetter 从请求中获取票据
type TicketGetter func(c echo.Context) string

type VerifyFunc = users.VerifyFunc

type UserNotFound = users.UserNotFound

// DbConfig 服务的数据库配置项
type DbConfig = users.DbConfig

type LockedUser = users.LockedUser
type UserManager = users.UserManager

// Config 服务的配置项
type Config struct {
	//数字验证码配置
	Captcha         base64Captcha.ConfigDigit
	Theme           string
	URLPrefix       string
	PlayPath        string
	ClientTitleText string
	HeaderTitleText string
	FooterTitleText string
	LogoPath        string
	TampletePaths   []string

	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool

	NewUserURL       string
	WelcomeURL       string
	RedirectMode     string
	CookiesForLogout []*http.Cookie

	ListenAt string

	TicketLookup   string
	TicketProtocol string
	TicketConfig   map[string]interface{}
}

// CreateServer 创建一个 sso 服务
func CreateServer(config *Config, userManager UserManager, online users.Sessions) (*Server, error) {
	if strings.HasSuffix(config.URLPrefix, "/") {
		config.URLPrefix = strings.TrimSuffix(config.URLPrefix, "/")
	}
	if config.CookiePath == "" {
		config.CookiePath = "/"
	} else if !strings.HasPrefix(config.CookiePath, "/") {
		config.CookiePath = "/" + config.CookiePath
	}

	templateBox, err := rice.FindBox("static")
	if err != nil {
		return nil, errors.New("load static directory fail, " + err.Error())
	}

	tokenName := "token"
	ticketGetter := ticketFromQueryAndCookie(tokenName)
	if config.TicketLookup != "" {
		parts := strings.Split(config.TicketLookup, ":")
		if len(parts) != 2 {
			return nil, errors.New("TicketLookup(" + config.TicketLookup + ") is invalid")
		}

		tokenName = parts[1]
		switch parts[0] {
		case "query":
			ticketGetter = ticketFromQuery(parts[1])
		case "cookie":
			ticketGetter = ticketFromCookie(parts[1])
		case "header":
			ticketGetter = ticketFromHeader(parts[1])
		case "query_and_cookie":
			ticketGetter = ticketFromQueryAndCookie(parts[1])
		}
	}

	logger := log.New(os.Stderr, "[sso] ", log.LstdFlags|log.Lshortfile)

	// UserConfig     interface{}
	// AuthConfig     interface{}

	//	userManager, online, err := DefaultUserHandler(config, logger)
	//	if err != nil {
	//		return nil, err
	//	}

	factory := TicketHandlerFactories[config.TicketProtocol]
	if factory == nil {
		return nil, errors.New("protocl '" + config.TicketProtocol + "' is unsupported.")
	}
	ticketHandler, err := factory(config.TicketConfig)
	if err != nil {
		return nil, err
	}

	variables := map[string]interface{}{}
	variables["url_prefix"] = config.URLPrefix
	variables["play_path"] = config.PlayPath
	variables["application_context"] = config.URLPrefix

	variables["client_title_text"] = config.ClientTitleText
	variables["header_title_text"] = config.HeaderTitleText
	variables["footer_title_text"] = config.FooterTitleText
	variables["logo_png"] = config.LogoPath
	variables["new_user_url"] = config.NewUserURL

	// Echo instance
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.MethodOverrideWithConfig(middleware.MethodOverrideConfig{
		Getter: func(c echo.Context) string {
			m := c.FormValue("_method")
			if m != "" {
				return m
			}
			return c.QueryParam("_method")
		}}))
	srv := &Server{
		Engine:         e,
		cookieDomain:   config.CookieDomain,
		cookiePath:     config.CookiePath,
		cookieSecure:   config.CookieSecure,
		cookieHTTPOnly: config.CookieHTTPOnly,
		theme:          config.Theme,
		urlPrefix:      config.URLPrefix,
		welcomeURL:     config.WelcomeURL,
		UserManager:    userManager,
		Online:         online,
		tokenName:      tokenName,
		ticketGetter:   ticketGetter,
		tickets:        ticketHandler,
		authenticatingTickets: authenticatingTickets{
			timeout: 1 * time.Minute,
			tickets: map[string]*authenticatingTicket{},
		},
		logger: logger,
		redirect: func(c echo.Context, toURL string) error {
			return c.Redirect(http.StatusTemporaryRedirect, toURL)
		},
		captcha:          config.Captcha,
		data:             variables,
		cookiesForLogout: config.CookiesForLogout,
	}

	if config.RedirectMode == "html" {
		srv.redirect = func(c echo.Context, toURL string) error {
			data := map[string]interface{}{
				"global":    srv.data,
				"returnURL": toURL,
			}
			return c.Render(http.StatusOK, "success.html", data)
		}
	}

	if len(config.TampletePaths) == 0 {
		config.TampletePaths = append(config.TampletePaths, filepath.Join("lib/web/sso"))
	}
	srv.Engine.Renderer = &renderer{
		srv:           srv,
		templates:     map[string]*template.Template{},
		templateRoots: config.TampletePaths,
		templateBox:   templateBox,
	}

	fs := http.FileServer(templateBox.HTTPBox())
	assetHandler := http.StripPrefix(config.URLPrefix+"/static/",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upath := r.URL.Path
			if strings.HasPrefix(upath, "/") {
				upath = strings.TrimPrefix(upath, "/")
			}
			for _, root := range config.TampletePaths {
				filename := filepath.Join(root, "static", upath)
				if _, err := os.Stat(filename); err == nil {
					http.ServeFile(w, r, filename)
					return
				}
			}

			fs.ServeHTTP(w, r)
		}))

	srv.Engine.GET(config.URLPrefix+"/debug/*", echo.WrapHandler(http.StripPrefix(config.URLPrefix, http.DefaultServeMux)))
	srv.Engine.GET(config.URLPrefix+"/static/*", echo.WrapHandler(assetHandler))
	srv.Engine.GET(config.URLPrefix+"/login", srv.loginGet)
	srv.Engine.POST(config.URLPrefix+"/login", srv.login)
	srv.Engine.POST(config.URLPrefix+"/logout", srv.logout)
	srv.Engine.GET(config.URLPrefix+"/logout", srv.logout)
	//srv.Engine.GET("/auth", srv.getTicket)
	srv.Engine.GET(config.URLPrefix+"/verify", srv.verifyTicket)
	//srv.Engine.POST("/verify", srv.verifyTickets)

	srv.Engine.GET(config.URLPrefix+"/locked_users", srv.lockedUsers)
	srv.Engine.GET(config.URLPrefix+"/unlock_user", srv.userUnlock)

	srv.Engine.GET(config.URLPrefix+"/captcha", echo.WrapHandler(http.HandlerFunc(users.GenerateCaptcha(config.Captcha))))
	// srv.Engine.PUT(config.URLPrefix+"/captcha", echo.WrapHandler(http.HandlerFunc(captchaVerify(config.Captcha.Digit))))

	return srv, nil
}

// Server SSO 服务器
type Server struct {
	Engine                *echo.Echo
	theme                 string
	cookieDomain          string
	cookiePath            string
	cookieSecure          bool
	cookieHTTPOnly        bool
	urlPrefix             string
	welcomeURL            string
	tokenName             string
	UserManager           users.UserManager
	Online                users.Sessions
	tickets               TicketHandler
	ticketGetter          TicketGetter
	authenticatingTickets authenticatingTickets
	logger                *log.Logger
	captcha               interface{}
	redirect              func(c echo.Context, url string) error
	data                  map[string]interface{}

	cookiesForLogout []*http.Cookie
}

type renderer struct {
	srv           *Server
	templatesLock sync.Mutex
	templates     map[string]*template.Template
	templateRoots []string
	templateBox   *rice.Box
}

func (r *renderer) Render(wr io.Writer, name string, data interface{}, c echo.Context) error {
	var t *template.Template
	var err error
	if name == "login.html" {
		theme := c.QueryParam("theme")
		if theme == "" {
			theme = r.srv.theme
		}

		if theme != "" {
			t, err = r.loadTemplate("login_" + theme + ".html")
			if err != nil {
				r.srv.logger.Println("[warn] load login_"+theme+".html", err)
			}
		}
	}
	if t == nil {
		t, err = r.loadTemplate(name)
		if err != nil {
			return err
		}
	}
	return t.Execute(wr, data)
}

var funcs = template.FuncMap{
	"query": url.QueryEscape,
	"htmlattr": func(s string) template.HTMLAttr {
		return template.HTMLAttr(s)
	},
	"html": func(s string) template.HTML {
		return template.HTML(s)
	},
	"js": func(s string) template.JS {
		return template.JS(s)
	},
	"set_src": func(s string) template.Srcset {
		return template.Srcset(s)
	},
	"jsstr": func(s string) template.JSStr {
		return template.JSStr(s)
	},
}

func (r *renderer) loadTemplate(name string) (*template.Template, error) {
	r.templatesLock.Lock()
	t := r.templates[name]
	r.templatesLock.Unlock()
	if t != nil {
		return t, nil
	}

	for _, pa := range r.templateRoots {
		filename := filepath.Join(pa, name)
		bs, err := ioutil.ReadFile(filename)
		if err == nil {
			t, err = template.New(name).Funcs(funcs).Parse(string(bs))
			if err != nil {
				r.srv.logger.Println("failed to load template(", name, ") from ", filename, ", ", err)
				return nil, err
			}
			r.srv.logger.Println("load template(", name, ") from ", filename)
			break
		}

		if !os.IsNotExist(err) {
			r.srv.logger.Println("failed to load template(", name, ") from ", filename, ", ", err)
			return nil, err
		}
	}

	if t == nil {
		bs, err := r.templateBox.Bytes(name)
		if err != nil {
			r.srv.logger.Println("failed to load template(", name, ") from rice box, ", err)
			return nil, err
		}
		if len(bs) == 0 {
			r.srv.logger.Println("failed to load template(", name, ") from rice box, file is empty.")
			return nil, err
		}

		t, err = template.New(name).Funcs(funcs).Parse(string(bs))
		if err != nil {
			r.srv.logger.Println("failed to load template(", name, ") from rice box, ", err)
			return nil, err
		}
	}

	if !isDebug {
		r.templatesLock.Lock()
		r.templates[name] = t
		r.templatesLock.Unlock()
	}
	return t, nil
}

// Start starts an HTTP server.
func (srv *Server) Start(address string) error {
	return srv.Engine.Start(address)
}

// StartTLS starts an HTTPS server.
func (srv *Server) StartTLS(address string, certFile, keyFile string) (err error) {
	return srv.Engine.StartTLS(address, certFile, keyFile)
}

// StartAutoTLS starts an HTTPS server using certificates automatically installed from https://letsencrypt.org.
func (srv *Server) StartAutoTLS(address string) error {
	return srv.Engine.StartAutoTLS(address)
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.Engine.ServeHTTP(w, r)
}

func (srv *Server) lockedUsers(c echo.Context) error {
	ticketString := srv.ticketGetter(c)
	if ticketString == "" {
		return c.String(http.StatusUnauthorized, "Unauthorized")
	}

	_, err := srv.tickets.ValidateTicket(ticketString, true)
	if err != nil {
		return c.String(http.StatusUnauthorized, err.Error())
	}

	return srv.lockedUsersWithError(c, nil)
}

func (srv *Server) lockedUsersWithError(c echo.Context, unlocked error) error {
	users, err := srv.UserManager.Locked()
	data := map[string]interface{}{"global": srv.data,
		"users": users}
	if err != nil {
		data["error"] = err.Error()
	}
	if unlocked != nil {
		data["error"] = unlocked.Error()
	}

	return c.Render(http.StatusOK, "locked_users.html", data)
}

func (srv *Server) userUnlock(c echo.Context) error {
	ticketString := srv.ticketGetter(c)
	if ticketString == "" {
		return c.String(http.StatusUnauthorized, "Unauthorized")
	}

	_, err := srv.tickets.ValidateTicket(ticketString, true)
	if err != nil {
		return c.String(http.StatusUnauthorized, err.Error())
	}

	username := c.QueryParam("username")
	err = srv.UserManager.Unlock(username)
	return srv.lockedUsersWithError(c, err)
}

func (srv *Server) loginGet(c echo.Context) error {
	ticketString := srv.ticketGetter(c)
	if ticketString != "" {
		ticket, err := srv.tickets.ValidateTicket(ticketString, true)
		if err == nil && ticket != nil {

			service := c.QueryParam("service")
			if service == "" {
				service = srv.welcomeURL
			}

			return srv.loginOK(c, ticket, service)
		}
	}

	method := c.QueryParam("_method")
	if method == "POST" {
		return srv.login(c)
	}

	service := c.QueryParam("service")
	if service == "" {
		service = srv.welcomeURL
	}
	data := map[string]interface{}{"global": srv.data,
		"service": service}
	return c.Render(http.StatusOK, "login.html", data)
}

func (srv *Server) relogin(c echo.Context, loginInfo users.LoginInfo, message string, err error) error {
	if ErrCaptchaKey == err {
		message = "请输入验证码"
	} else if ErrCaptchaMissing == err {
		message = "验证码错误"
	} else if ErrUserIPBlocked == err {
		message = "用户不能在该地址访问"
	} else if err == ErrUserLocked {
		message = "错误次数大多，帐号被锁定！"
	} else if err == ErrPermissionDenied {
		message = "用户没有访问权限"
	} else if err == ErrMutiUsers {
		message = "同名的用户有多个"
	} else if IsErrExternalServer(err) {
		message = err.Error()
	} else {
		if message == "" {
			message = "用户名或密码不正确!"
		}
	}

	data := map[string]interface{}{"global": srv.data,
		"service": loginInfo.Service,
		// "login_fail_count": loginInfo.LoginFailCount,
		"username":     loginInfo.Username,
		"errorMessage": message,
	}

	if count := srv.UserManager.FailCount(loginInfo.Username); count > 0 {
		captchaID := "" // time.Now().Format(time.RFC3339Nano)
		data["captcha_id"] = captchaID
		captchaKey, captchaCode := base64Captcha.GenerateCaptcha(captchaID, srv.captcha)
		data["captcha_data"] = base64Captcha.CaptchaWriteToBase64Encoding(captchaCode)
		data["captcha_key"] = captchaKey
	}

	if err == ErrUserAlreadyOnline {
		data["showForce"] = true
	}
	return c.Render(http.StatusOK, "login.html", data)
}

func (srv *Server) alreadyLoginOnOtherHost(c echo.Context, loginInfo users.LoginInfo, onlineList []users.SessionInfo) error {
	if len(onlineList) == 1 {
		if !isConsumeJSON(c) {
			return srv.relogin(c, loginInfo, "用户已在 "+onlineList[0].Address+
				" 上登录，最后一次活动时间为 "+
				onlineList[0].UpdatedAt.Format("2006-01-02 15:04:05Z07:00"), ErrUserAlreadyOnline)
		}
		return echo.NewHTTPError(http.StatusUnauthorized,
			"user is already online, login with address is '"+
				onlineList[0].Address+
				"' and time is "+
				onlineList[0].UpdatedAt.Format("2006-01-02 15:04:05Z07:00"))
	}

	if !isConsumeJSON(c) {
		return srv.relogin(c, loginInfo, "用户已在其他机器上登录", ErrUserAlreadyOnline)
	}
	return ErrUserAlreadyOnline
}

func (srv *Server) login(c echo.Context) error {
	var loginInfo users.LoginInfo
	if err := c.Bind(&loginInfo); err != nil {
		srv.logger.Println("登录数据的格式不正确 -", err)

		if !isConsumeJSON(c) {
			data := map[string]interface{}{"global": srv.data,
				"errorMessage": "登录数据的格式不正确",
			}

			return c.Render(http.StatusOK, "login.html", data)
		}
		return echo.ErrUnauthorized
	}
	if loginInfo.Username == "" {
		if isConsumeJSON(c) {
			return c.String(http.StatusUnauthorized, "请输入用户名")
		}

		return srv.relogin(c, loginInfo, "请输入用户名", nil)
	}

	loginInfo.Address = RealIP(c.Request())

	userinfo, err := users.Auth(srv.UserManager, &loginInfo)
	if err != nil || userinfo == nil {
		if err == nil {
			err = ErrUserNotFound
		}
		if onlineList, ok := users.IsOnlinedError(err); ok {
			return srv.alreadyLoginOnOtherHost(c, loginInfo, onlineList)
		}
	}

	if err != nil {
		srv.logger.Println("用户授权失败 -", err)

		if !isConsumeJSON(c) {
			return srv.relogin(c, loginInfo, "", err)
		}

		// 不要将过多的信息暴露给用户，仅将特定的信息返回
		for _, excepted := range []error{
			ErrPasswordNotMatch,
			ErrUserNotFound,
			ErrUserLocked,
			ErrUserIPBlocked,
			ErrCaptchaKey,
			ErrCaptchaMissing,
		} {
			if err == excepted {
				return err
			}
		}
		if IsErrExternalServer(err) {
			return err
		}
		return echo.ErrUnauthorized
	}

	uuid, err := srv.Online.Login(userinfo.ID, userinfo.Address, userinfo.Service)
	if err != nil {
		srv.logger.Println("创建在线用户失败 -", err)
	}

	ticket, err := srv.tickets.NewTicket(uuid, loginInfo.Username, userinfo.Data)
	if err != nil {
		srv.logger.Println("内部生成 ticket 失败 -", err)

		if !isConsumeJSON(c) {
			return srv.relogin(c, loginInfo, "", err)
		}
		return echo.ErrUnauthorized
	}

	return srv.loginOK(c, ticket, userinfo.Service)
}

func (srv *Server) loginOK(c echo.Context, ticket *Ticket, service string) error {
	serviceTicket := srv.authenticatingTickets.new(ticket, service)

	c.SetCookie(&http.Cookie{Name: srv.tokenName,
		Value: ticket.Ticket,
		Path:  srv.cookiePath,
		// Expires: ticket.ExpiresAt, // 不指定过期时间，那么关闭浏览器后 cookie 会删除
	})
	if service != "" {
		returnURL := service
		u, err := url.Parse(returnURL)
		if err == nil {
			queryParams := u.Query()
			queryParams.Set("ticket", serviceTicket)
			queryParams.Set("session_id", ticket.SessionID)
			queryParams.Set("username", ticket.Username)
			if o := ticket.Data["is_new"]; o != nil {
				queryParams.Set("is_new", fmt.Sprint(o))
				if o := ticket.Data["roles"]; o != nil {
					switch vv := o.(type) {
					case []string:
						queryParams["roles"] = vv
					case []interface{}:
						ss := make([]string, 0, len(vv))
						for _, v := range vv {
							ss = append(ss, fmt.Sprint(v))
						}
						queryParams["roles"] = ss
					}
				}
			}
			u.RawQuery = queryParams.Encode()
			returnURL = u.String()
		}

		return srv.redirect(c, returnURL)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"ticket":     serviceTicket,
		"session_id": ticket.SessionID,
		"username":   ticket.Username,
	})
}

func (srv *Server) logout(c echo.Context) error {
	var ticket *Ticket
	ticketString := srv.ticketGetter(c)
	if ticketString != "" {
		var err error
		ticket, err = srv.tickets.RemoveTicket(ticketString)
		if err != nil {
			srv.logger.Println("删除 ticket 失败 -", err)
			return echo.NewHTTPError(http.StatusUnauthorized, "删除 ticket 失败 - "+err.Error())
		}
	} else {
		srv.logger.Println("ticket 不存在")
	}

	if ticket != nil {
		err := srv.Online.Logout(ticket.SessionID)
		if err != nil {
			srv.logger.Println("删除 在线用户 失败 -", err)
		}
	}

	c.SetCookie(&http.Cookie{Name: srv.tokenName,
		Value:   "",
		Path:    srv.cookiePath,
		Expires: time.Now(),
		MaxAge:  -1})
	for _, cookie := range srv.cookiesForLogout {
		c.SetCookie(&http.Cookie{Name: cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			Raw:      cookie.Raw,
			Unparsed: cookie.Unparsed,
			Expires:  time.Now(),
			MaxAge:   -1})
	}

	returnURL := c.QueryParam("service")
	if !isConsumeJSON(c) {
		if returnURL == "" {
			returnURL = srv.urlPrefix + "/login"
		}
	}

	if returnURL != "" {
		u, err := url.Parse(returnURL)
		if err == nil {
			queryParams := u.Query()
			queryParams.Del("ticket")
			u.RawQuery = queryParams.Encode()
			returnURL = u.String()
		}
		return srv.redirect(c, returnURL)
	}

	return c.String(http.StatusOK, "OK")
}

func (srv *Server) verifyTicket(c echo.Context) error {
	serviceTicket := c.QueryParam("ticket")
	if serviceTicket == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "ticket 不存在")
	}
	service := c.QueryParam("service")

	ticket, err := srv.authenticatingTickets.fetchAndValidate(serviceTicket, service)
	if err != nil {
		srv.logger.Println("验证 ticket 失败 -", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "验证 ticket 失败 - "+err.Error())
	}
	if ticket == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{"ticket": serviceTicket, "valid": false})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"ticket":     serviceTicket,
		"username":   ticket.Username,
		"session_id": ticket.SessionID,
		"valid":      true,
		"expires_at": ticket.ExpiresAt,
		"claims":     ticket.Data})
}

// func (srv *Server) verifyTickets(c echo.Context) error {
// 	var ticketStrings []string
// 	if err := c.Bind(&ticketStrings); err != nil {
// 		return echo.NewHTTPError(http.StatusBadRequest, "读 ticket 列表失败 - "+err.Error())
// 	}
//
// 	results := make([]map[string]interface{}, 0, len(ticketStrings))
// 	for _, ticketString := range ticketStrings {
// 		ticket, err := srv.tickets.ValidateTicket(ticketString)
// 		if err != nil {
// 			results = append(results, map[string]interface{}{
// 				"ticket": ticketString,
// 				"valid":  false,
// 				"error":  err.Error()})
// 		} else {
// 			results = append(results, map[string]interface{}{"id": ticket.ID,
// 				"ticket":     ticket.Ticket,
// 				"valid":      true,
// 				"expires_at": ticket.ExpiresAt,
// 				"claims":     ticket.Data})
// 		}
// 	}
// 	return c.JSON(http.StatusOK, results)
// }

func ticketFromQuery(name string) TicketGetter {
	return func(c echo.Context) string {
		return c.QueryParam(name)
	}
}

func ticketFromCookie(name string) TicketGetter {
	return func(c echo.Context) string {
		cookie, err := c.Cookie(name)
		if err != nil {
			return ""
		}

		return cookie.Value
	}
}

func ticketFromQueryAndCookie(name string) TicketGetter {
	return func(c echo.Context) string {
		if value := c.QueryParam(name); value != "" {
			return value
		}

		cookie, err := c.Cookie(name)
		if err != nil {
			return ""
		}

		return cookie.Value
	}
}

func ticketFromHeader(header string) TicketGetter {
	return func(c echo.Context) string {
		return c.Request().Header.Get(header)
	}
}

func isConsumeJSON(c echo.Context) bool {
	accept := c.Request().Header.Get("Accept")
	contentType := c.Request().Header.Get(echo.HeaderContentType)
	return strings.Contains(contentType, echo.MIMEApplicationJSON) &&
		strings.Contains(accept, echo.MIMEApplicationJSON)
}

func readFileWithDefault(root string, files []string, defaultValue string) string {
	for _, s := range files {
		content, e := ioutil.ReadFile(filepath.Join(root, s))
		if nil == e {
			if content = bytes.TrimSpace(content); len(content) > 0 {
				return string(content)
			}
		}
	}
	return defaultValue
}

func Run(config *Config) {
	srv, err := CreateServer(config)
	if err != nil {
		srv.logger.Println(err)
		return
	}

	err = srv.Start(config.ListenAt)
	if err != nil {
		srv.logger.Println(err)
		return
	}
}
