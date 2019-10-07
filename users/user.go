package users

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/three-plus-three/modules/netutil"
)

type LoginInfo struct {
	Username   string `json:"username" xml:"username" form:"username" query:"username"`
	Password   string `json:"password" xml:"password" form:"password" query:"password"`
	Service    string `json:"service" xml:"service" form:"service" query:"service"`
	ForceLogin string `json:"force,omitempty" xml:"force" form:"force" query:"force"`

	CaptchaKey   string `json:"captcha_key,omitempty" xml:"captcha_key" form:"captcha_key" query:"captcha_key"`
	CaptchaValue string `json:"captcha_value,omitempty" xml:"captcha_value" form:"captcha_value" query:"captcha_value"`

	Address   string
	NoCaptcha bool
}

func (u *LoginInfo) IsForce() bool {
	u.ForceLogin = strings.ToLower(u.ForceLogin)
	return u.ForceLogin == "on" ||
		u.ForceLogin == "true" ||
		u.ForceLogin == "checked"
}

type UserInfo struct {
	LoginInfo
	IsNew    bool
	ID       interface{}
	SessonID string
	Data     map[string]interface{}
}

func (u *UserInfo) RawName() string {
	if u.Data == nil {
		return u.Username
	}
	if o := u.Data["user"]; o != nil {
		if s, ok := o.(string); ok {
			return s
		}
	}

	if o := u.Data["username"]; o != nil {
		if s, ok := o.(string); ok {
			return s
		}
	}
	return ""
}

func (u *UserInfo) Roles() []string {
	if !u.IsNew {
		return nil
	}
	if u.Data == nil {
		return nil
	}
	o := u.Data["roles"]
	if o == nil {
		return nil
	}
	switch vv := o.(type) {
	case []string:
		return vv
	case []interface{}:
		ss := make([]string, 0, len(vv))
		for _, v := range vv {
			ss = append(ss, fmt.Sprint(v))
		}
		return ss
	}
	return nil
}

type Authentication interface {
	Auth(loginInfo *LoginInfo) (*UserInfo, error)
}

type LocalUser interface {
	ID() interface{}
	Username() string
	Data() map[string]interface{}
}

// VerifyFunc 用户验证回调类型，method 为扩展类型， inner 为数据库中保存的数据 loginInfo 为界面上用户填写的
type VerifyFunc func(method string, localUser LocalUser, loginInfo *LoginInfo) (*UserInfo, error)

// UserNotFound 用户不存在时的回调
type UserNotFound func(loginInfo *LoginInfo) (bool, map[string]interface{}, error)

var localAddressList, _ = net.LookupHost("localhost")

type UserImpl struct {
	verify            func(password, excepted string) error
	externalVerify    VerifyFunc
	id                interface{}
	name              string
	password          string
	lockedAt          time.Time
	lockedTimeExpires time.Duration
	ingressIPList     []netutil.IPChecker
	data              map[string]interface{}
	// failCount         int
}

func (u *UserImpl) ID() interface{} {
	return u.id
}

func (u *UserImpl) Username() string {
	return u.name
}

func (u *UserImpl) Password() string {
	return u.password
}

// func (u *UserImpl) FailCount() int {
// 	return u.failCount
// }

func (u *UserImpl) isValid(currentAddr string) (bool, error) {
	if len(u.ingressIPList) != 0 {
		ip := net.ParseIP(currentAddr)
		if ip == nil {
			return false, errors.New("client address is invalid - '" + currentAddr + "'")
		}

		blocked := true
		for _, checker := range u.ingressIPList {
			if checker.Contains(ip) {
				blocked = false
				break
			}
		}

		if blocked {
			if "127.0.0.1" == currentAddr {
				blocked = false
			} else {
				for _, addr := range localAddressList {
					if currentAddr == addr {
						blocked = false
						break
					}
				}

				if blocked {
					return false, ErrUserIPBlocked
				}
			}
		}
	}

	if !u.lockedAt.IsZero() && u.name != "admin" {
		if u.lockedTimeExpires == 0 {
			return false, ErrUserLocked
		}
		if time.Now().Before(u.lockedAt.Add(u.lockedTimeExpires)) {
			return false, ErrUserLocked
		}
	}
	return true, nil
}

func (u *UserImpl) Data() map[string]interface{} {
	return u.data
}

func (u *UserImpl) Auth(loginInfo *LoginInfo) (*UserInfo, error) {
	ok, err := u.isValid(loginInfo.Address)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("user is inused")
	}

	var method string
	if typ := u.data["source"]; typ != nil {
		method = fmt.Sprint(typ)
	}

	if method != "" && method != "builin" {
		if u.externalVerify == nil {
			return nil, errors.New("externalVerify is disabled")
		}
		return u.externalVerify(method, u, loginInfo)
	}

	exceptedPassword := u.Password()
	if exceptedPassword == "" {
		return nil, ErrPasswordEmpty
	}

	err = u.verify(loginInfo.Password, exceptedPassword)
	if err != nil {
		if err == ErrSignatureInvalid {
			return nil, ErrPasswordNotMatch
		}
		return nil, err
	}
	uinfo := &UserInfo{
		LoginInfo: *loginInfo,
		ID:        u.id,
		Data:      u.data,
	}
	if u.name != "" {
		uinfo.Username = u.name
	}
	return uinfo, nil
}
