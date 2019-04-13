package users

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/three-plus-three/modules/netutil"
)

type UserInfo struct {
	Username   string `json:"username" xml:"username" form:"username" query:"username"`
	Password   string `json:"password" xml:"password" form:"password" query:"password"`
	Service    string `json:"service" xml:"service" form:"service" query:"service"`
	ForceLogin string `json:"force,omitempty" xml:"force" form:"force" query:"force"`

	CaptchaKey   string `json:"captcha_key,omitempty" xml:"captcha_key" form:"captcha_key" query:"captcha_key"`
	CaptchaValue string `json:"captcha_value,omitempty" xml:"captcha_value" form:"captcha_value" query:"captcha_value"`

	Address string
}

func (u *UserInfo) IsForce() bool {
	return u.ForceLogin == "on" ||
		u.ForceLogin == "true" ||
		u.ForceLogin == "checked"
}

type User interface {
	Name() string
	Data() map[string]interface{}
}

// VerifyFunc 用户验证回调类型，method 为扩展类型， inner 为数据库中保存的数据 userinfo 为界面上用户填写的
type VerifyFunc func(method string, inner InternalUser, userinfo *UserInfo) error

// UserNotFound 用户不存在时的回调
type UserNotFound func(userinfo *UserInfo) (map[string]interface{}, error)

var localAddressList, _ = net.LookupHost("localhost")

type UserImpl struct {
	verify            func(password, excepted string) error
	externalVerify    VerifyFunc
	name              string
	password          string
	lockedAt          time.Time
	lockedTimeExpires time.Duration
	ingressIPList     []netutil.IPChecker
	data              map[string]interface{}
	// failCount         int
}

func (u *UserImpl) Name() string {
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

func (u *UserImpl) Auth(userinfo *UserInfo) error {
	ok, err := u.isValid(userinfo.Address)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("user is inused")
	}

	var method string
	if typ := u.data["source"]; typ != nil {
		method = fmt.Sprint(typ)
	}

	if method != "" && method != "builin" {
		return u.externalVerify(method, u, userinfo)
	}

	exceptedPassword := u.Password()
	if exceptedPassword == "" {
		return ErrPasswordEmpty
	}

	err = u.verify(userinfo.Password, exceptedPassword)
	if err != nil {
		if err == ErrSignatureInvalid {
			return ErrPasswordNotMatch
		}
		return err
	}
	return nil
}
