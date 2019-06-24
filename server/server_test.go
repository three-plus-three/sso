package server

import (
	"bytes"
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	_ "net/http/pprof"
	"net/url"
	"strings"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	_ "github.com/lib/pq"
	"github.com/three-plus-three/sso/client"
	"github.com/three-plus-three/sso/client/echo_sso"
	"golang.org/x/net/publicsuffix"
)

var dbType = flag.String("db.type", "postgres", "")
var dbURL = flag.String("db.url", "host=127.0.0.1 port=5432 dbname=ssotest user=ssotest password=123456 sslmode=disable", "")

type serverTest struct {
	srv    *Server
	db     *sql.DB
	hsrv   *httptest.Server
	client *client.Client
}

func (srv *serverTest) Close() error {
	srv.hsrv.CloseClientConnections()
	srv.hsrv.Close()
	return srv.db.Close() //srv.client.Close()
}

func MakeTestConfig() *Config {
	config := &Config{
		UserConfig: &DbConfig{
			DbType: *dbType,
			DbURL:  *dbURL},
		TicketProtocol: "jwt",
		//TicketConfig:   map[string]interface{}{},
	}

	return config
}
func MakeDbConfig() *DbConfig {

	return &DbConfig{
		DbType: *dbType,
		DbURL:  *dbURL}

	return config
}

var (
	adminPWD   = "admin"
	zhuPWD     = "aaa"
	testMethod = jwt.SigningMethodHS256
	testKey    = []byte("asdfagsfe")

	signTestParams = map[string]interface{}{"passwordHashAlg": testMethod.Alg(),
		"passwordHashKey": string(testKey)}
	userTestParams = map[string]interface{}{
		"querySQL":  "SELECT * FROM users WHERE username = ?",
		"lockSQL":   "UPDATE users SET locked_at = ? WHERE username = ?",
		"unlockSQL": "UPDATE users SET locked_at = NULL WHERE username = ?",
		"lockedSQL": "SELECT * FROM users WHERE locked_at IS NOT NULL",
	}
)

func makeMD5(signingString string) string {
	s, _ := testMethod.Sign(signingString, testKey)
	return s
}

func startTest(t *testing.T, table string, config *Config) *serverTest {
	db, err := sql.Open(config.UserConfig.(*DbConfig).DbType,
		config.UserConfig.(*DbConfig).DbURL)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	defer db.Close()

	if table == "" {
		table = "users"
	}
	online_table := "online_users"

	_, err = db.Exec(`
DROP TABLE IF EXISTS ` + table + ` CASCADE;
CREATE TABLE ` + table + ` (
  id             serial PRIMARY KEY,
  username       VARCHAR(200) NOT NULL,
  password        VARCHAR(100) NOT NULL,
  white_addresses VARCHAR(100),

  email          VARCHAR(100),
  location       VARCHAR(100),
  locked_at      timestamp
);


DROP TABLE IF EXISTS ` + online_table + ` CASCADE;
CREATE TABLE ` + online_table + ` (
  uuid           VARCHAR(50) PRIMARY KEY,
  user_id        int  references ` + table + `(id),
  address        VARCHAR(30) NOT NULL,

  created_at      timestamp,
  updated_at      timestamp
);

insert into ` + table + `(username, password, email, location, white_addresses) values('admin', '` + adminPWD + `', 'admin@a.com', 'system user', '["192.168.1.2"]');
insert into ` + table + `(username, password, email, location, white_addresses) values('white', '` + adminPWD + `', 'white@a.com', 'white user', '["192.168.1.2"]');
insert into ` + table + `(username, password, email, location) values('mei', 'aat', 'mei@a.com', 'an hui');
insert into ` + table + `(username, password, email, location) values('zhu', '` + makeMD5(zhuPWD) + `', 'zhu@a.com', 'shanghai');
`)

	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	db.Close()

	srv, err := CreateServer(config)

	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	hsrv := httptest.NewServer(srv)

	cli, err := client.NewClient(hsrv.URL)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	conn, err := sql.Open(config.UserConfig.(*DbConfig).DbType,
		config.UserConfig.(*DbConfig).DbURL)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	return &serverTest{srv: srv,
		db:     conn,
		hsrv:   hsrv,
		client: cli}
}

func TestLoginWithUserNotFound(t *testing.T) {
	srv := startTest(t, "", MakeTestConfig())
	defer srv.Close()

	_, err := srv.client.NewTicket("user_not_exists", "aat", false)
	if err == nil {
		t.Error("except error, but success")
		return
	}

	if err != client.ErrUserNotFound {
		t.Error("except error code is ErrUserNotFound, actual is", err)
	}
}

func TestLoginWithPasswordError(t *testing.T) {
	srv := startTest(t, "", MakeTestConfig())
	defer srv.Close()

	_, err := srv.client.NewTicket("mei", "password_is_error", false)
	if err == nil {
		t.Error("except error, but success")
		return
	}

	if err != client.ErrPasswordNotMatch {
		t.Error("except error code is ErrPasswordNotMatch, actual is", err)
	}
}

func TestLoginWithDefault(t *testing.T) {
	srv := startTest(t, "", MakeTestConfig())
	defer srv.Close()

	ticket, err := srv.client.NewTicket("mei", "aat", false)
	if err != nil {
		t.Error(err)
		return
	}
	if len(ticket.Claims) == 0 {
		t.Error("claims is empty")
		return
	}

	for _, test := range [][2]string{{"email", "mei@a.com"}, {"location", "an hui"}} {
		value := ticket.Claims[test[0]]
		if test[1] != fmt.Sprint(value) {
			t.Error("field '"+test[0]+"' is error, excepted is", test[1], ",actual is", value)
		}
	}

	_, err = srv.client.ValidateTicket(ticket.ServiceTicket, "")
	if err == nil {
		t.Error("excepted error, but not")
	}
}

func TestLoginWithMD5Hash(t *testing.T) {
	config := MakeTestConfig()
	config.AuthConfig = signTestParams

	srv := startTest(t, "", config)
	defer srv.Close()

	ticket, err := srv.client.NewTicket("zhu", zhuPWD, false)
	if err != nil {
		t.Error(err)
		return
	}
	if len(ticket.Claims) == 0 {
		t.Error("claims is empty")
		return
	}

	for _, test := range [][2]string{{"email", "zhu@a.com"}, {"location", "shanghai"}} {
		value := ticket.Claims[test[0]]
		if test[1] != fmt.Sprint(value) {
			t.Error("field '"+test[0]+"' is error, excepted is", test[1], ",actual is", value)
		}
	}
}

func TestLoginWithMD5HashAndPasswordError(t *testing.T) {
	config := MakeTestConfig()
	config.AuthConfig = signTestParams

	srv := startTest(t, "", config)
	defer srv.Close()

	_, err := srv.client.NewTicket("zhu", "aaaa", false)
	if err == nil {
		t.Error("except error, but success")
		return
	}

	if err != client.ErrPasswordNotMatch {
		t.Error("except error code is ErrPasswordNotMatch, actual is", err)
	}
}

func TestLoginFailAndLocked(t *testing.T) {
	config := MakeTestConfig()
	config.UserConfig.(*DbConfig).Params = userTestParams
	config.AuthConfig = signTestParams

	srv := startTest(t, "", config)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		_, err := srv.client.NewTicket("zhu", "aaaa", false)
		if err == nil {
			t.Error("except error, but success")
			return
		}

		if err != client.ErrPasswordNotMatch {
			if strings.Contains(err.Error(), fmt.Sprint(ErrUserLocked.Message)) {
				break
			}
			t.Error("except error code is ErrPasswordNotMatch, actual is", err)
		}
	}

	_, err := srv.client.NewTicket("zhu", zhuPWD, false)
	if err == nil {
		t.Error("except error, but success")
		return
	}

	if !strings.Contains(err.Error(), fmt.Sprint(ErrUserLocked.Message)) {
		t.Error("except error code is ErrPasswordNotMatch, actual is", err)
	}
}

func TestLoginFailAndCountLessMaxNotLocked(t *testing.T) {
	config := MakeTestConfig()
	config.UserConfig.(*DbConfig).Params = userTestParams
	config.AuthConfig = signTestParams
	config.MaxLoginFailCount = 3

	srv := startTest(t, "", config)
	defer srv.Close()

	for i := 0; i < config.MaxLoginFailCount; i++ {
		_, err := srv.client.NewTicket("zhu", "aaaa", false)
		if err == nil {
			t.Error("except error, but success")
			return
		}

		if err != client.ErrPasswordNotMatch {
			t.Error("except error code is ErrPasswordNotMatch, actual is", err)
		}
	}

	_, err := srv.client.NewTicket("zhu", zhuPWD, false)
	if err != nil {
		t.Error(err)
		return
	}

	for i := 0; i < config.MaxLoginFailCount; i++ {
		_, err := srv.client.NewTicket("zhu", "aaaa", false)
		if err == nil {
			t.Error("except error, but success")
			return
		}

		if err != client.ErrPasswordNotMatch {
			t.Error("except error code is ErrPasswordNotMatch, actual is", err)
		}
	}
}

func TestAdminLoginFailAndNotLocked(t *testing.T) {
	config := MakeTestConfig()
	config.UserConfig.(*DbConfig).Params = userTestParams
	//config.AuthConfig = signTestParams

	srv := startTest(t, "", config)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		_, err := srv.client.NewTicket("admin", "aaaa", false)
		if err == nil {
			t.Error("except error, but success")
			return
		}

		if err != client.ErrPasswordNotMatch {
			if strings.Contains(err.Error(), fmt.Sprint(ErrUserLocked.Message)) {
				break
			}
			t.Error("except error code is ErrPasswordNotMatch, actual is", err)
		}
	}

	_, err := srv.client.NewTicket("admin", adminPWD, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestAdminLoginOkAndIPNotBlock(t *testing.T) {
	config := MakeTestConfig()
	config.UserConfig.(*DbConfig).Params = userTestParams
	//config.AuthConfig = signTestParams

	srv := startTest(t, "", config)
	defer srv.Close()

	_, err := srv.client.NewTicket("admin", adminPWD, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestLoginFailAndIPBlock(t *testing.T) {
	config := MakeTestConfig()
	config.UserConfig.(*DbConfig).Params = userTestParams
	//config.AuthConfig = signTestParams

	srv := startTest(t, "", config)
	defer srv.Close()

	srv.client.SetHeader(HeaderXForwardedFor, "192.168.1.3")
	_, err := srv.client.NewTicket("white", adminPWD, false)
	if err == nil {
		t.Error("except error, but success")
		return
	}

	if !strings.Contains(err.Error(), fmt.Sprint(ErrUserIPBlocked.Message)) {
		t.Error("except error code is ErrUserIPBlocked, actual is", err)
	}

	srv.client.SetHeader(HeaderXForwardedFor, "192.168.1.2")
	_, err = srv.client.NewTicket("white", adminPWD, false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestLoginWithQuerySQL(t *testing.T) {
	config := MakeTestConfig()
	config.UserConfig.(*DbConfig).Params = map[string]interface{}{"querySQL": "SELECT * FROM hengwei_users WHERE username = ?"}
	config.AuthConfig = signTestParams

	srv := startTest(t, "hengwei_users", config)
	defer srv.Close()

	ticket, err := srv.client.NewTicket("zhu", zhuPWD, false)
	if err != nil {
		t.Error(err)
		return
	}
	if len(ticket.Claims) == 0 {
		t.Error("claims is empty")
		return
	}

	for _, test := range [][2]string{{"email", "zhu@a.com"}, {"location", "shanghai"}} {
		value := ticket.Claims[test[0]]
		if test[1] != fmt.Sprint(value) {
			t.Error("field '"+test[0]+"' is error, excepted is", test[1], ",actual is", value)
		}
	}
}

func TestLoginWithRedirect(t *testing.T) {
	srv := startTest(t, "", MakeTestConfig())
	defer srv.Close()

	text := "welcome ok"
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(echo_sso.SSOWithConfig("query", "ticket", "", srv.client))
	e.GET("welcome", func(c echo.Context) error {
		return c.String(http.StatusOK, text)
	})
	web := httptest.NewServer(e)
	defer web.Close()

	resp, err := http.Get(srv.hsrv.URL +
		"/login?_method=POST&username=" + url.QueryEscape("mei") +
		"&password=" + url.QueryEscape("aat") +
		"&service=" + url.QueryEscape(web.URL+"/welcome"))

	if err != nil {
		t.Error(err)
		return
	}

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if text != string(bs) {
		t.Error(string(bs))
	}
}

func TestLoginAndLogout(t *testing.T) {
	srv := startTest(t, "", MakeTestConfig())
	defer srv.Close()

	ssoClient, err := client.NewClient(srv.hsrv.URL)
	if err != nil {
		t.Error(err)
		return
	}

	text := "welcome ok"

	var e1URL string
	e1 := echo.New()
	e1.Use(middleware.Logger())
	e1.Use(middleware.Recover())
	welcome1 := func(c echo.Context) error {
		st := c.QueryParam("ticket")
		if st == "" {
			redirectURL := srv.hsrv.URL + "/login?service=" + url.QueryEscape(e1URL)
			return c.Redirect(http.StatusTemporaryRedirect, redirectURL)
		}

		ticket, err := ssoClient.ValidateTicket(st, "")
		if err != nil {
			if e, ok := err.(*client.Error); ok {
				return echo.NewHTTPError(e.Code, e.Message)
			}
			return echo.NewHTTPError(echo.ErrUnauthorized.Code, err.Error())
		}
		if !ticket.Valid {
			t.Log("ValidateTicket fail")
			return echo.ErrUnauthorized
		}

		return c.String(http.StatusOK, text)
	}
	e1.GET("/welcome", welcome1)
	e1.POST("/welcome", welcome1) // 重定向时，所使用的方法是与重定向之前是一致的。

	e1.HTTPErrorHandler = func(err error, c echo.Context) {
		t.Log(c.Request().Method, c.Request().URL)
		e1.DefaultHTTPErrorHandler(err, c)
	}
	web1 := httptest.NewServer(e1)
	defer web1.Close()
	e1URL = web1.URL + "/welcome"

	var e2URL string
	e2 := echo.New()
	e2.Use(middleware.Logger())
	e2.Use(middleware.Recover())
	e2.GET("/welcome", func(c echo.Context) error {
		st := c.QueryParam("ticket")
		if st == "" {
			redirectURL := srv.hsrv.URL + "/login?service=" + url.QueryEscape(e2URL)
			return c.Redirect(http.StatusTemporaryRedirect, redirectURL)
		}
		ticket, err := ssoClient.ValidateTicket(st, "")
		if err != nil {
			if e, ok := err.(*client.Error); ok {
				return echo.NewHTTPError(e.Code, e.Message)
			}
			return echo.NewHTTPError(echo.ErrUnauthorized.Code, err.Error())
		}
		if !ticket.Valid {
			return echo.ErrUnauthorized
		}
		return c.String(http.StatusOK, text)
	})

	e2.HTTPErrorHandler = func(err error, c echo.Context) {
		t.Log(c.Request().Method, c.Request().URL)
		e2.DefaultHTTPErrorHandler(err, c)
	}
	web2 := httptest.NewServer(e2)
	defer web2.Close()
	e2URL = web2.URL + "/welcome"

	// All users of cookiejar should import "golang.org/x/net/publicsuffix"
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Jar: jar,
	}

	t.Log("测试访问未登录页面时自动转到原来的页面")
	resp, err := client.Get(e1URL)
	if err != nil {
		t.Error(err)
		return
	}

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Error(resp.Status)
		t.Error(string(bs))
		return
	}

	for _, excepted := range []string{`<input type="hidden" name="service" value="` + e1URL + `" />`,
		"loginform", "用户名", "密码"} {
		if !bytes.Contains(bs, []byte(excepted)) {
			t.Error(string(bs))
			t.Error(excepted)
			return
		}
	}

	t.Log("测试提交用户名和密码后自动转到原来的页面")
	form := make(url.Values)
	form.Set("username", "mei")
	form.Set("password", "aat")
	form.Set("service", e1URL)
	resp, err = client.PostForm(srv.hsrv.URL+"/login", form)
	if err != nil {
		t.Error(err)
		return
	}

	bs, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Error(resp.Status)
		t.Error(string(bs))
		return
	}

	if text != string(bs) {
		t.Error(string(bs))
		t.Log(e1URL)
		t.Log(e2URL)
	}

	t.Log("测试访问第二个页面时无需登录")
	resp, err = client.Get(e2URL)
	if err != nil {
		t.Error(err)
		return
	}

	bs, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Error(resp.Status)
		t.Error(string(bs))
		return
	}

	if text != string(bs) {
		t.Error(string(bs))
	}

	t.Log("测试用户注销页面")
	resp, err = client.Get(srv.hsrv.URL + "/logout")
	if err != nil {
		t.Error(err)
		return
	}

	bs, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Error(resp.Status)
		t.Error(string(bs))
		return
	}

	t.Log("验证注销是否成功")
	resp, err = client.Get(e2URL)
	if err != nil {
		t.Error(err)
		return
	}

	bs, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		t.Error(resp.Status)
		t.Error(string(bs))
		return
	}

	for _, excepted := range []string{`<input type="hidden" name="service" value="` + e2URL + `" />`,
		"loginform", "用户名", "密码"} {
		if !bytes.Contains(bs, []byte(excepted)) {
			t.Error(string(bs))
			t.Error(excepted)
			return
		}
	}
}
