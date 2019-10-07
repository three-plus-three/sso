package server

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/mojocn/base64Captcha"
	"github.com/three-plus-three/sso/client"
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

type AuthResult struct {
	SessionID string
	IsNewUser bool
	Data      map[string]interface{}
}

type AuthFunc func(*LoginContext) error

type LoginContext struct {
	Context context.Context

	UserID       interface{} `json:"userid" xml:"userid" form:"-" query:"-"`
	Username     string      `json:"username" xml:"username" form:"username" query:"username"`
	Password     string      `json:"password" xml:"password" form:"password" query:"password"`
	Service      string      `json:"service" xml:"service" form:"service" query:"service"`
	ForceLogin   string      `json:"force,omitempty" xml:"force" form:"force" query:"force"`
	CaptchaKey   string      `json:"captcha_key,omitempty" xml:"captcha_key" form:"captcha_key" query:"captcha_key"`
	CaptchaValue string      `json:"captcha_value,omitempty" xml:"captcha_value" form:"captcha_value" query:"captcha_value"`

	Address   string
	NoCaptcha bool

	Authentication AuthFunc
}

type SessionManager interface {
	Login(ctx *LoginContext) (*AuthResult, error)
	Logout(sessonID, username, loginAddress string)
}

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

	SessionKey       string
	SessionPath      string
	SessionDomain    string
	SessionSecure    bool
	SessionHttpOnly  bool
	SessionHashFunc  string
	SessionSecretKey []byte

	NewUserURL       string
	WelcomeURL       string
	RedirectMode     string
	CookiesForLogout []*http.Cookie

	ListenAt string

	// TicketLookup   string
	// TicketProtocol string
	// TicketConfig   map[string]interface{}
}

// Server SSO 服务器
type Server struct {
	engine         *echo.Echo
	config         Config
	sessonHashFunc func() hash.Hash
	sessionMgr     SessionManager
	logger         *log.Logger
	captcha        interface{}
	redirect       func(c echo.Context, url string) error
	data           map[string]interface{}
}

func (srv *Server) Route() *echo.Group {
	return srv.engine.Group(srv.config.URLPrefix)
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
			theme = r.srv.config.Theme
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
	return srv.engine.Start(address)
}

// StartTLS starts an HTTPS server.
func (srv *Server) StartTLS(address string, certFile, keyFile string) (err error) {
	return srv.engine.StartTLS(address, certFile, keyFile)
}

// StartAutoTLS starts an HTTPS server using certificates automatically installed from https://letsencrypt.org.
func (srv *Server) StartAutoTLS(address string) error {
	return srv.engine.StartAutoTLS(address)
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.engine.ServeHTTP(w, r)
}

func (srv *Server) loginGet(c echo.Context) error {
	// ticketString := srv.ticketGetter(c)
	// if ticketString != "" {
	// 	ticket, err := srv.tickets.ValidateTicket(ticketString, true)
	// 	if err == nil && ticket != nil {

	// 		service := c.QueryParam("service")
	// 		if service == "" {
	// 			service = srv.welcomeURL
	// 		}

	// 		return srv.loginOK(c, ticket, service)
	// 	}
	// }

	method := c.QueryParam("_method")
	if method == "POST" {
		return srv.login(c)
	}

	service := c.QueryParam("service")
	if service == "" {
		service = srv.config.WelcomeURL
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
	var loginInfo LoginContext
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

	loginInfo.Context = c.Request().Context()
	loginInfo.NoCaptcha = false
	loginInfo.Address = RealIP(c.Request())

	loginResult, err := srv.sessionMgr.Login(&loginInfo)
	if err != nil || loginResult == nil {
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

	var values = url.Values{}

	for k, v := range loginResult.Data {
		found := false
		for _, s := range []string{
			"uuid",
			"username",
			"password",
			"name",
			"expired_at",
			"issued_at",
			"admin"} {
			if s == k {
				found = true
				break
			}
		}
		if found {
			continue
		}
		values.Set(k, fmt.Sprint(v))
	}

	values.Set("issued_at", time.Now().Format(time.RFC3339))
	values.Set(client.SESSION_ID_KEY, loginResult.SessonID)
	values.Set(client.SESSION_EXPIRE_KEY, "session")
	values.Set(client.SESSION_VALID_KEY, "true")
	values.Set(client.SESSION_USER_KEY, loginInfo.Username)

	c.SetCookie(&http.Cookie{
		Name:     srv.config.SessionKey,
		Value:    client.Encode(values, srv.sessonHashFunc, srv.config.SessionSecretKey),
		Domain:   srv.config.SessionDomain,
		Path:     srv.config.SessionPath,
		Secure:   srv.config.SessionSecure,
		HttpOnly: srv.config.SessionHttpOnly,
	})

	if loginInfo.Service != "" {
		return srv.redirect(c, loginInfo.Service)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"userid":     loginInfo.UserID,
		"username":   loginInfo.Username,
		"session_id": loginResult.SessionID,
		"is_new":     loginResult.IsNew,
		"roles":      loginResult.Roles(),
	})
}

func (srv *Server) logout(c echo.Context) error {
	values, err := client.GetValues(c.Request(),
		srv.config.SessionKey, srv.sessonHashFunc(), srv.config.SessionSecretKey)
	if err != nil {
		log.Println("fetch session fail,", err)
		return echo.ErrUnauthorized
	}

	sessionID := values.Get(client.SESSION_ID_KEY)
	username := values.Get(client.SESSION_USER_KEY)
	err = srv.sessionMgr.Logout(sessionID, username, c.RealIP())
	if err != nil {
		srv.logger.Println("删除 在线用户 失败 -", err)
	}

	values.Set(client.SESSION_EXPIRE_KEY, strconv.FormatInt(time.Now().Unix()-30*24*40, 10))
	values.Set(client.SESSION_VALID_KEY, "false")
	c.SetCookie(&http.Cookie{
		Name:     srv.config.SessionKey,
		Value:    client.Encode(values, srv.sessonHashFunc, srv.config.SessionSecretKey),
		Domain:   srv.config.SessionDomain,
		Path:     srv.config.SessionPath,
		Secure:   srv.config.SessionSecure,
		HttpOnly: srv.config.SessionHttpOnly,
		Expires:  time.Now(),
		MaxAge:   -1,
	})
	for _, cookie := range srv.config.CookiesForLogout {
		a := &http.Cookie{}
		*a = *cookie
		a.Expires = time.Now()
		a.MaxAge = -1
		c.SetCookie(a)
	}

	returnURL := c.QueryParam("service")
	if !isConsumeJSON(c) {
		if returnURL == "" {
			returnURL = srv.config.URLPrefix + "/login"
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

// func ticketFromQuery(name string) TicketGetter {
// 	return func(c echo.Context) string {
// 		return c.QueryParam(name)
// 	}
// }

// func ticketFromCookie(name string) TicketGetter {
// 	return func(c echo.Context) string {
// 		cookie, err := c.Cookie(name)
// 		if err != nil {
// 			return ""
// 		}

// 		return cookie.Value
// 	}
// }

// func ticketFromQueryAndCookie(name string) TicketGetter {
// 	return func(c echo.Context) string {
// 		if value := c.QueryParam(name); value != "" {
// 			return value
// 		}

// 		cookie, err := c.Cookie(name)
// 		if err != nil {
// 			return ""
// 		}

// 		return cookie.Value
// 	}
// }

// func ticketFromHeader(header string) TicketGetter {
// 	return func(c echo.Context) string {
// 		return c.Request().Header.Get(header)
// 	}
// }

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

// CreateServer 创建一个 sso 服务
func CreateServer(config *Config, sessionMgr SessionManager, online users.Sessions) (*Server, error) {
	if strings.HasSuffix(config.URLPrefix, "/") {
		config.URLPrefix = strings.TrimSuffix(config.URLPrefix, "/")
	}
	if config.SessionPath == "" {
		config.SessionPath = "/"
	} else if !strings.HasPrefix(config.SessionPath, "/") {
		config.SessionPath = "/" + config.SessionPath
	}

	templateBox, err := rice.FindBox("static")
	if err != nil {
		return nil, errors.New("load static directory fail, " + err.Error())
	}

	// tokenName := "token"
	// ticketGetter := ticketFromQueryAndCookie(tokenName)
	// if config.TicketLookup != "" {
	// 	parts := strings.Split(config.TicketLookup, ":")
	// 	if len(parts) != 2 {
	// 		return nil, errors.New("TicketLookup(" + config.TicketLookup + ") is invalid")
	// 	}

	// 	tokenName = parts[1]
	// 	switch parts[0] {
	// 	case "query":
	// 		ticketGetter = ticketFromQuery(parts[1])
	// 	case "cookie":
	// 		ticketGetter = ticketFromCookie(parts[1])
	// 	case "header":
	// 		ticketGetter = ticketFromHeader(parts[1])
	// 	case "query_and_cookie":
	// 		ticketGetter = ticketFromQueryAndCookie(parts[1])
	// 	}
	// }

	logger := log.New(os.Stderr, "[sso] ", log.LstdFlags|log.Lshortfile)

	// UserConfig     interface{}
	// AuthConfig     interface{}

	//	userManager, online, err := DefaultUserHandler(config, logger)
	//	if err != nil {
	//		return nil, err
	//	}

	// factory := TicketHandlerFactories[config.TicketProtocol]
	// if factory == nil {
	// 	return nil, errors.New("protocl '" + config.TicketProtocol + "' is unsupported.")
	// }
	// ticketHandler, err := factory(config.TicketConfig)
	// if err != nil {
	// 	return nil, err
	// }

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
		config:     *config,
		engine:     e,
		sessionMgr: sessionMgr,
		logger:     logger,
		redirect: func(c echo.Context, toURL string) error {
			return c.Redirect(http.StatusTemporaryRedirect, toURL)
		},
		captcha: config.Captcha,
		data:    variables,
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
	srv.engine.Renderer = &renderer{
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

	srv.sessonHashFunc = sha1.New
	switch srv.config.SessionHashFunc {
	case "", "sha1":
	case "md5", "MD5":
		srv.sessonHashFunc = md5.New
	}

	srv.engine.GET(config.URLPrefix+"/debug/*", echo.WrapHandler(http.StripPrefix(config.URLPrefix, http.DefaultServeMux)))
	srv.engine.GET(config.URLPrefix+"/static/*", echo.WrapHandler(assetHandler))
	srv.engine.GET(config.URLPrefix+"/login", srv.loginGet)
	srv.engine.POST(config.URLPrefix+"/login", srv.login)
	srv.engine.POST(config.URLPrefix+"/logout", srv.logout)
	srv.engine.GET(config.URLPrefix+"/logout", srv.logout)
	//srv.engine.GET("/auth", srv.getTicket)
	//srv.engine.GET(config.URLPrefix+"/verify", srv.verifyTicket)
	//srv.engine.POST("/verify", srv.verifyTickets)

	// srv.engine.GET(config.URLPrefix+"/locked_users", srv.lockedUsers)
	// srv.engine.GET(config.URLPrefix+"/unlock_user", srv.userUnlock)

	srv.engine.GET(config.URLPrefix+"/captcha", echo.WrapHandler(http.HandlerFunc(users.GenerateCaptcha(config.Captcha))))
	// srv.engine.PUT(config.URLPrefix+"/captcha", echo.WrapHandler(http.HandlerFunc(captchaVerify(config.Captcha.Digit))))

	return srv, nil
}
