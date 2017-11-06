package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/three-plus-three/modules/netutil"
)

var localAddressList, _ = net.LookupHost("localhost")

// DefaultUserHandler 缺省 UserHandler
var DefaultUserHandler = createDbUserHandler

type User interface {
	Name() string
	Auth(address, password string) error
	Data() map[string]interface{}
}

type UserImpl struct {
	externalVerify    VerifyFunc
	verify            func(password, excepted string) error
	name              string
	password          string
	lockedAt          time.Time
	lockedTimeExpires time.Duration
	ingressIPList     []netutil.IPChecker
	data              map[string]interface{}
}

func (u *UserImpl) Name() string {
	return u.name
}

func (u *UserImpl) Password() string {
	return u.password
}

const (
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"
)

func RealIP(req *http.Request) string {
	ra := req.RemoteAddr
	if ip := req.Header.Get(HeaderXForwardedFor); ip != "" {
		ra = ip
	} else if ip := req.Header.Get(HeaderXRealIP); ip != "" {
		ra = ip
	} else {
		ra, _, _ = net.SplitHostPort(ra)
	}
	return ra
}

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

	if !u.lockedAt.IsZero() {
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

func (u *UserImpl) Auth(address, password string) error {
	ok, err := u.isValid(address)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("user is inused")
	}

	if u.externalVerify != nil {
		if typ := u.data["source"]; typ != nil {
			if verifyType := fmt.Sprint(typ); verifyType != "" && verifyType != "builin" {
				return u.externalVerify(verifyType, u.name, password)
			}
		}
	}

	exceptedPassword := u.Password()
	if exceptedPassword == "" {
		return ErrPasswordEmpty
	}

	err = u.verify(password, exceptedPassword)
	if err != nil {
		if err == ErrSignatureInvalid {
			return ErrPasswordNotMatch
		}
		return err
	}
	return nil
}
