package server

import (
	"strings"
	"testing"

	"github.com/three-plus-three/sso/client"
)

var (
	onlineUserTestParams = map[string]interface{}{
		"querySQL":  "SELECT * FROM users WHERE username = ?",
		"lockSQL":   "UPDATE users SET locked_at = ? WHERE username = ?",
		"unlockSQL": "UPDATE users SET locked_at = NULL WHERE username = ?",
		"lockedSQL": "SELECT * FROM users WHERE locked_at IS NOT NULL",
		"online":    "db",
	}
)

func TestLoginFailAndAlreadyOnline(t *testing.T) {
	// config := MakeTestConfig()
	//config.UserConfig.(*DbConfig).Params = onlineUserTestParams
	//config.AuthConfig = signTestParams

	srv := startTest(t, "", MakeTestConfig(), MakeDbConfig())
	defer srv.Close()

	var assert = func(username string, exceptCount int) {
		var count int
		err := srv.db.QueryRow("select count(*) from online_users where exists(select * from users where online_users.user_id = users.id and users.username = $1)", username).Scan(&count)
		if err != nil {
			t.Error(err)
			return
		}

		if count != exceptCount {
			t.Error("except is", exceptCount, ", actual is", count)
		}
	}

	srv.client.SetHeader(HeaderXForwardedFor, "192.168.1.2")
	ticket, err := srv.client.NewTicket("mei", "aat", false)
	if err != nil {
		t.Error(err)
		return
	}

	assert("mei", 1)

	t.Log("确保再次登录是OK的")
	_, err = srv.client.NewTicket("mei", "aat", false)
	if err != nil {
		t.Error(err)
		return
	}

	assert("mei", 1)

	t.Log("用别的 IP 登录是不好的")
	client2, err := client.NewClient(srv.hsrv.URL)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	client2.SetHeader(HeaderXForwardedFor, "192.168.1.3")
	_, err = client2.NewTicket("mei", "aat", false)
	if err == nil {
		t.Error("except return user already online")
		return
	} else if !strings.Contains(err.Error(), "user is already online, login with address is '192.168.1.2'") {
		t.Error(err)
		return
	}

	t.Log("测试已退出后，再用别的 IP 登录是好的")
	srv.client.SetHeader(HeaderXForwardedFor, "192.168.1.2")
	err = srv.client.RemoveTicket(ticket.ServiceTicket)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = client2.NewTicket("mei", "aat", false)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestOnlineUserIsOkAfterAnotherLoginIsLogout(t *testing.T) {
	//config := MakeTestConfig()
	//config.UserConfig.(*DbConfig).Params = onlineUserTestParams
	//config.AuthConfig = signTestParams

	srv := startTest(t, "", MakeTestConfig(), MakeDbConfig())
	defer srv.Close()

	var assert = func(username string, exceptCount int) {
		t.Helper()

		var count int
		err := srv.db.QueryRow("select count(*) from online_users where exists(select * from users where online_users.user_id = users.id and users.username = $1)", username).Scan(&count)
		if err != nil {
			t.Error(err)
			return
		}

		if count != exceptCount {
			t.Error("except is", exceptCount, ", actual is", count)
		}
	}

	srv.client.SetHeader(HeaderXForwardedFor, "192.168.1.2")
	ticket, err := srv.client.NewTicket("mei", "aat", false)
	if err != nil {
		t.Error(err)
		return
	}

	assert("mei", 1)

	t.Log("确保再次登录是OK的")

	_, err = srv.client.NewTicket("mei", "aat", false)
	if err != nil {
		t.Error(err)
		return
	}

	assert("mei", 1)

	client2, err := client.NewClient(srv.hsrv.URL)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	client2.SetHeader(HeaderXForwardedFor, "192.168.1.3")
	_, err = client2.NewTicket("mei", "aat", true)
	if err != nil {
		t.Error(err)
		return
	}
	assert("mei", 2)

	err = srv.client.RemoveTicket(ticket.ServiceTicket)
	if err != nil {
		t.Error(err)
		return
	}
	assert("mei", 1)
}
