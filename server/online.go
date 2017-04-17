package server

import "time"

type OnlineUserInfo struct {
	Username  string
	Address   string
	ExpiresAt time.Time
	IssuedAt  time.Time
}

type Online interface {
	Save(info *OnlineUserInfo) error
	Delete(username, address string) error
}

type emptyOnline struct{}

func (em *emptyOnline) Save(info *OnlineUserInfo) error {
	return nil
}

func (em *emptyOnline) Delete(username, address string) error {
	return nil
}

var DefaultOnlineHandler = createEmptyOnline

func createEmptyOnline(params interface{}) (Online, error) {
	return &emptyOnline{}, nil
}

// func createDbOnline(params interface{}) (Online, error) {
// 	config, ok := params.(*DbConfig)
// 	if !ok {
// 		return nil, errors.New("arguments of UserConfig isn't DbConfig")
// 	}

// 	if config.Params != nil {
// 		if o, ok := config.Params["username"]; ok && o != nil {
// 			s, ok := o.(string)
// 			if !ok {
// 				return nil, errors.New("数据库配置中的 username 的值不是字符串")
// 			}
// 			if s = strings.TrimSpace(s); s != "" {
// 				userFieldName = s
// 			}
// 		}
// }

/*
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
*/
