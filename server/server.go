package server

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
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
)

var (
	isDebug = os.Getenv("IsSSODebug") == "true"

	// ErrUsernameEmpty 用户名为空
	ErrUsernameEmpty = echo.NewHTTPError(http.StatusUnauthorized, "user name is empty")

	// ErrPasswordEmpty 密码为空
	ErrPasswordEmpty = echo.NewHTTPError(http.StatusUnauthorized, "user password is empty")

	// ErrUserNotFound 用户未找到
	ErrUserNotFound = echo.NewHTTPError(http.StatusUnauthorized, "user isn't found")

	// ErrPasswordNotMatch 密码不正确
	ErrPasswordNotMatch = echo.NewHTTPError(http.StatusUnauthorized, "password isn't match")

	// ErrMutiUsers 找到多个用户
	ErrMutiUsers = echo.NewHTTPError(http.StatusUnauthorized, "muti users is found")

	// ErrUserLocked 用户已被锁定
	ErrUserLocked = echo.NewHTTPError(http.StatusUnauthorized, "user is locked")

	// ErrUserIPBlocked 用户不在指定的 IP 范围登录
	ErrUserIPBlocked = echo.NewHTTPError(http.StatusUnauthorized, "user address is blocked")

	// ErrServiceTicketNotFound Service ticket 没有找到
	ErrServiceTicketNotFound = echo.NewHTTPError(http.StatusUnauthorized, "service ticket isn't found")

	// ErrServiceTicketExpired Service ticket 已过期
	ErrServiceTicketExpired = echo.NewHTTPError(http.StatusUnauthorized, "service ticket isn't expired")

	// ErrUnauthorizedService Service 是未授权的
	ErrUnauthorizedService = echo.NewHTTPError(http.StatusUnauthorized, "service is unauthorized")
)

// TicketGetter 从请求中获取票据
type TicketGetter func(c echo.Context) string

type Config struct {
	UrlPrefix       string
	HeaderTitleText string
	FooterTitleText string
	LogoPath        string
	TampletePaths   []string
	IsLockByAddress bool

	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieHttpOnly bool

	MaxLoginFailCount int
	WelcomeURL        string
	RedirectMode      string
	CookiesForLogout  []*http.Cookie

	ListenAt       string
	UserConfig     interface{}
	AuthConfig     interface{}
	TicketLookup   string
	TicketProtocol string
	TicketConfig   map[string]interface{}
}

type DbConfig struct {
	DbType   string
	Address  string
	Port     string
	DbName   string
	Username string
	Password string

	Params map[string]interface{}
}

func (db *DbConfig) URL() (string, string) {
	switch db.DbType {
	case "postgresql", "postgres":
		if db.Port == "" {
			db.Port = "5432"
		}
		return "postgres", fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
			db.Address, db.Port, db.DbName, db.Username, db.Password)
	case "mysql":
		if db.Port == "" {
			db.Port = "3306"
		}
		return "mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
			db.Username, db.Password, db.Address, db.Port, db.DbName)
	default:
		panic(errors.New("unknown db type - " + db.DbType))
	}
}

// CreateServer 创建一个 sso 服务
func CreateServer(config *Config) (*Server, error) {
	if strings.HasSuffix(config.UrlPrefix, "/") {
		config.UrlPrefix = strings.TrimSuffix(config.UrlPrefix, "/")
	}
	if config.CookiePath == "" {
		config.CookiePath = "/"
	} else if !strings.HasPrefix(config.CookiePath, "/") {
		config.CookiePath = "/" + config.CookiePath
	}
	if config.MaxLoginFailCount <= 0 {
		config.MaxLoginFailCount = 3
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

	if DefaultUserHandler == nil {
		DefaultUserHandler = createDbUserHandler
	}
	if DefaultAuthenticationHandler == nil {
		DefaultAuthenticationHandler = CreateUserAuthenticationHandler
	}

	userHandler, err := DefaultUserHandler(config.UserConfig)
	if err != nil {
		return nil, err
	}

	authenticationHandler, err := DefaultAuthenticationHandler(userHandler, config.AuthConfig)
	if err != nil {
		return nil, err
	}

	factory := TicketHandlerFactories[config.TicketProtocol]
	if factory == nil {
		return nil, errors.New("protocl '" + config.TicketProtocol + "' is unsupported.")
	}
	ticketHandler, err := factory(config.TicketConfig)
	if err != nil {
		return nil, err
	}

	variables := map[string]interface{}{}
	variables["url_prefix"] = config.UrlPrefix
	variables["application_context"] = config.UrlPrefix
	variables["header_title_text"] = config.HeaderTitleText
	variables["footer_title_text"] = config.FooterTitleText
	variables["logo_png"] = config.LogoPath

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
		engine:            e,
		cookieDomain:      config.CookieDomain,
		cookiePath:        config.CookiePath,
		cookieSecure:      config.CookieSecure,
		cookieHttpOnly:    config.CookieHttpOnly,
		urlPrefix:         config.UrlPrefix,
		welcomeURL:        config.WelcomeURL,
		IsLockByAddress:   config.IsLockByAddress,
		userHandler:       userHandler,
		auth:              authenticationHandler,
		tokenName:         tokenName,
		maxLoginFailCount: config.MaxLoginFailCount,
		ticketGetter:      ticketGetter,
		tickets:           ticketHandler,
		authenticatingTickets: authenticatingTickets{
			timeout: 1 * time.Minute,
			tickets: map[string]*authenticatingTicket{},
		},
		userLocks: CreateUserLocks(),
		redirect: func(c echo.Context, toURL string) error {
			return c.Redirect(http.StatusTemporaryRedirect, toURL)
		},
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
	srv.engine.Renderer = &renderer{
		srv:           srv,
		templates:     map[string]*template.Template{},
		templateRoots: config.TampletePaths,
		templateBox:   templateBox,
	}

	fs := http.FileServer(templateBox.HTTPBox())
	assetHandler := http.StripPrefix(config.UrlPrefix+"/static/",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upath := r.URL.Path
			if strings.HasPrefix(upath, "/") {
				upath = strings.TrimPrefix(upath, "/")
			}
			for _, root := range config.TampletePaths {
				filename := filepath.Join(root, upath)
				if _, err := os.Stat(filename); err == nil {
					http.ServeFile(w, r, filename)
					return
				}
			}

			fs.ServeHTTP(w, r)
		}))
	srv.engine.GET(config.UrlPrefix+"/static/*", echo.WrapHandler(assetHandler))
	srv.engine.GET(config.UrlPrefix+"/login", srv.loginGet)
	srv.engine.POST(config.UrlPrefix+"/login", srv.login)
	srv.engine.POST(config.UrlPrefix+"/logout", srv.logout)
	srv.engine.GET(config.UrlPrefix+"/logout", srv.logout)
	//srv.engine.GET("/auth", srv.getTicket)
	srv.engine.GET(config.UrlPrefix+"/verify", srv.verifyTicket)
	//srv.engine.POST("/verify", srv.verifyTickets)

	srv.engine.GET(config.UrlPrefix+"/locked_users", srv.lockedUsers)
	srv.engine.GET(config.UrlPrefix+"/unlock_user", srv.userUnlock)

	return srv, nil
}

// Server SSO 服务器
type Server struct {
	engine                *echo.Echo
	cookieDomain          string
	cookiePath            string
	cookieSecure          bool
	cookieHttpOnly        bool
	urlPrefix             string
	welcomeURL            string
	tokenName             string
	maxLoginFailCount     int
	userHandler           UserHandler
	auth                  AuthenticationHandler
	tickets               TicketHandler
	ticketGetter          TicketGetter
	authenticatingTickets authenticatingTickets
	userLocks             UserLocks

	IsLockByAddress     bool
	addressesByUserLock sync.Mutex
	addressesByUser     map[string]string

	redirect func(c echo.Context, url string) error
	data     map[string]interface{}

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
		t, err = r.loadTemplate("login_" + theme + ".html")
		if err != nil {
			fmt.Println(err)
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
				log.Println("failed to load template(", name, ") from ", filename, ", ", err)
				return nil, err
			}
			log.Println("load template(", name, ") from ", filename)
			break
		}

		if !os.IsNotExist(err) {
			log.Println("failed to load template(", name, ") from ", filename, ", ", err)
			return nil, err
		}
	}

	if t == nil {
		bs, err := r.templateBox.Bytes(name)
		if err != nil {
			log.Println("failed to load template(", name, ") from rice box, ", err)
			return nil, err
		}
		if len(bs) == 0 {
			log.Println("failed to load template(", name, ") from rice box, file is empty.")
			return nil, err
		}

		t, err = template.New(name).Funcs(funcs).Parse(string(bs))
		if err != nil {
			log.Println("failed to load template(", name, ") from rice box, ", err)
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

type userLogin struct {
	Username       string `json:"username" xml:"username" form:"username" query:"username"`
	Password       string `json:"password" xml:"password" form:"password" query:"password"`
	Service        string `json:"service" xml:"service" form:"service" query:"service"`
	LoginFailCount int    `json:"login_fail_count" xml:"login_fail_count" form:"login_fail_count" query:"login_fail_count"`
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
	users, err := srv.userHandler.LockedUsers()
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
	err = srv.userHandler.UnlockUser(username)
	if err == nil {
		srv.userLocks.Zero(username)
	}
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

func (srv *Server) relogin(c echo.Context, user userLogin, message string) error {
	if message == "" {
		message = "用户名或密码不正确!"
	}

	data := map[string]interface{}{"global": srv.data,
		"service":          user.Service,
		"login_fail_count": user.LoginFailCount,
		"username":         user.Username,
		"errorMessage":     message,
	}
	return c.Render(http.StatusOK, "login.html", data)
}

func (srv *Server) login(c echo.Context) error {
	var user userLogin
	if err := c.Bind(&user); err != nil {
		log.Println("登录数据的格式不正确 -", err)

		if !isConsumeJSON(c) {
			return c.Render(http.StatusOK, "login.html", srv.data)
		}
		return echo.ErrUnauthorized
	}
	if srv.IsLockByAddress {
		if locked := srv.isLockedByAddress(c, &user); locked {
			if !isConsumeJSON(c) {
				return srv.relogin(c, user, "用户已登录")
			}
			return echo.ErrUnauthorized
		}
	}

	/*
		var failCount = srv.userLocks.Count(user.Username)
		if failCount > srv.maxLoginFailCount && "admin" != user.Username {
			if err := srv.userHandler.LockUser(user.Username); err != nil {
				log.Println("lock", user.Username, "fail,", err)
			}
			user.LoginFailCount = failCount
			if !isConsumeJSON(c) {
				return srv.relogin(c, user, "错误次数大多，帐号被锁定！")
			}

			return ErrUserLocked
		}
	*/

	authOK, userData, err := srv.auth.Auth(c.Request(), user.Username, user.Password)
	if err != nil {
		log.Println("用户授权失败 -", err)

		if err == ErrPasswordNotMatch && "admin" != user.Username {
			srv.userLocks.FailOne(user.Username)
			var failCount = srv.userLocks.Count(user.Username)
			if failCount > srv.maxLoginFailCount {
				if err := srv.userHandler.LockUser(user.Username); err != nil {
					log.Println("lock", user.Username, "fail,", err)
				}
			}
		}

		if !isConsumeJSON(c) {
			if ErrUserIPBlocked == err {
				return srv.relogin(c, user, "用户不能在该地址访问")
			}
			return srv.relogin(c, user, "")
		}

		if err == ErrPasswordNotMatch {
			return err
		}
		if err == ErrUserNotFound {
			return err
		}
		if err == ErrUserLocked {
			return err
		}
		return echo.ErrUnauthorized
	}
	if !authOK {
		if !isConsumeJSON(c) {
			return srv.relogin(c, user, "")
		}

		return ErrPasswordNotMatch
	}

	ticket, err := srv.tickets.NewTicket(user.Username, userData)
	if err != nil {
		log.Println("内部生成 ticket 失败 -", err)

		if !isConsumeJSON(c) {
			return srv.relogin(c, user, "")
		}
		return echo.ErrUnauthorized
	}

	return srv.loginOK(c, ticket, user.Service)
}

var localAddressList, _ = net.LookupHost("localhost")

func (srv *Server) isLockedByAddress(c echo.Context, user *userLogin) bool {
	if user.Username == "admin" {
		return false
	}

	realAddr := c.RealIP()
	if "" == realAddr {
		return false
	}
	if "127.0.0.1" == realAddr {
		srv.addressesByUserLock.Lock()
		defer srv.addressesByUserLock.Unlock()
		if srv.addressesByUser == nil {
			srv.addressesByUser = map[string]string{}
		}
		srv.addressesByUser[user.Username] = realAddr
		return false
	}
	for _, addr := range localAddressList {
		if realAddr == addr {
			srv.addressesByUserLock.Lock()
			defer srv.addressesByUserLock.Unlock()
			if srv.addressesByUser == nil {
				srv.addressesByUser = map[string]string{}
			}
			srv.addressesByUser[user.Username] = realAddr
			return false
		}
	}

	srv.addressesByUserLock.Lock()
	defer srv.addressesByUserLock.Unlock()

	fmt.Println(srv.addressesByUser)
	if len(srv.addressesByUser) == 0 {
		srv.addressesByUser = map[string]string{user.Username: realAddr}
		return false
	} else if oldAddr, ok := srv.addressesByUser[user.Username]; !ok {
		srv.addressesByUser[user.Username] = realAddr
		return false
	} else {
		for _, excepted := range []string{"", realAddr} {
			if excepted == oldAddr {
				return false
			}
		}
	}
	return true
}

func (srv *Server) loginOK(c echo.Context, ticket *Ticket, service string) error {
	serviceTicket := srv.authenticatingTickets.new(ticket, service)

	c.SetCookie(&http.Cookie{Name: srv.tokenName,
		Value: ticket.Ticket,
		Path:  "/",
		// Expires: ticket.ExpiresAt, // 不指定过期时间，那么关闭浏览器后 cookie 会删除
	})
	if service != "" {
		returnURL := service
		u, err := url.Parse(service)
		if err == nil {
			queryParams := u.Query()
			queryParams.Set("ticket", serviceTicket)
			u.RawQuery = queryParams.Encode()
			returnURL = u.String()
		}

		return srv.redirect(c, returnURL)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"ticket": serviceTicket})
}

func (srv *Server) logout(c echo.Context) error {
	var ticket *Ticket
	ticketString := srv.ticketGetter(c)
	if ticketString != "" {
		var err error
		ticket, err = srv.tickets.RemoveTicket(ticketString)
		if err != nil {
			log.Println("删除 ticket 失败 -", err)
			return echo.NewHTTPError(http.StatusUnauthorized, "删除 ticket 失败 - "+err.Error())
		}
	} else {
		log.Println("ticket 不存在")
	}

	if srv.IsLockByAddress && ticket != nil {
		func() {
			srv.addressesByUserLock.Lock()
			defer srv.addressesByUserLock.Unlock()
			if len(srv.addressesByUser) > 0 {
				delete(srv.addressesByUser, ticket.Username)
			}
		}()
	}

	c.SetCookie(&http.Cookie{Name: srv.tokenName,
		Value:   "",
		Path:    "/",
		Expires: time.Now().Add(1 * time.Second),
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
			Expires:  time.Now().Add(1 * time.Second),
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
		log.Println("验证 ticket 失败 -", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "验证 ticket 失败 - "+err.Error())
	}
	if ticket == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{"ticket": serviceTicket, "valid": false})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"ticket": serviceTicket,
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
		log.Println(err)
		return
	}

	err = srv.Start(config.ListenAt)
	if err != nil {
		log.Println(err)
		return
	}
}
