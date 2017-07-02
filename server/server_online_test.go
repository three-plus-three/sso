package server

import (
	"strings"
	"testing"
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
	config := MakeTestConfig()
	config.UserConfig.(*DbConfig).Params = onlineUserTestParams
	//config.AuthConfig = signTestParams

	srv := startTest(t, "", config)
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
	ticket, err := srv.client.NewTicket("mei", "aat")
	if err != nil {
		t.Error(err)
		return
	}

	assert("mei", 1)

	// 确保再次登录是OK的
	_, err = srv.client.NewTicket("mei", "aat")
	if err != nil {
		t.Error(err)
		return
	}

	assert("mei", 1)

	srv.client.SetHeader(HeaderXForwardedFor, "192.168.1.3")
	_, err = srv.client.NewTicket("mei", "aat")
	if err == nil {
		t.Error("except return user already online")
		return
	} else if !strings.Contains(err.Error(), "user is already online, login with address is '192.168.1.2'") {
		t.Error(err)
		return
	}

	err = srv.client.RemoveTicket(ticket.ServiceTicket)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = srv.client.NewTicket("mei", "aat")
	if err != nil {
		t.Error(err)
		return
	}
}
